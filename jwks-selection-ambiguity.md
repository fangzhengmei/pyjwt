# JWKS selection ambiguity and the verification trust boundary

Scope: this checkout of PyJWT 2.15.1 (`jwt/api_jwk.py`, `jwt/jwks_client.py`,
`jwt/api_jws.py`, `jwt/algorithms.py`). All observations below were produced
locally with generated keys and tokens — no network, no third-party JWKS, no
modification to repository files. The harness is
`/tmp/jwks93/repro_jwks_selection.py`; observation IDs `O1`–`O24` in this
document are the `== On` sections of its output.

Every claim is tagged:

* **[source]** — read directly off the code, with a `file:line` citation.
* **[observed]** — produced by the harness in this environment
  (Python 3.12.3, `cryptography` 41.0.7, `has_crypto = True`).
* **[gap]** — no test in this repository currently pins this behaviour, or the
  evidence is indirect and needs a dedicated test to become durable.

The question this document answers: when a JWK Set simultaneously contains
duplicate `kid`s, keys with different `use`, malformed curve parameters, and
entries whose `alg` disagrees with the signing algorithm, *which* key does the
verification path pick, and how does that choice fail?

---

## 1. Short answer

There is no "verification selection chain" in the sense of a ranked,
explainable choice. There are three independent, order-sensitive selectors that
never consult each other:

1. **`PyJWK` construction** (`jwt/api_jwk.py:30-87`) silently drops or
   reinterprets entries. It picks an algorithm from `alg` if truthy, otherwise
   *infers* one from `kty`/`crv`. It never compares `alg` against `crv`, and it
   never calls `ECAlgorithm._validate_curve`.
2. **`PyJWKSet.__init__`** (`jwt/api_jwk.py:141-165`) keeps every entry that
   constructs, in input order, and discards every entry whose `PyJWK` raised a
   `PyJWTError` — with no record of *why*. Unsupported algorithm and corrupt
   key material become the same outcome: absence.
3. **`PyJWKClient`** (`jwt/jwks_client.py:251-333`) applies its own `use`/`kid`
   filter and then `match_kid` returns the **first** entry whose `kid` compares
   equal, with `break`.

`PyJWS._verify_signature` then binds verification to the single selected
`PyJWK`'s `algorithm_name` (`jwt/api_jws.py:408-430`). So the algorithm that
actually verifies the signature is decided by *position in the published JSON
array*, filtered by a silent-drop pass. For a duplicate `kid` that resolves to
the wrong entry, the result is a hard failure, not a fallback; for an attacker
who can influence that ordering, it is a silent change of trust anchor.

The trust boundary is therefore: **first constructible entry with a matching
`kid` wins, and "constructible" is a weaker property than "correct".**

---

## 2. Source evidence for each selector

### 2.1 Algorithm resolution order in `PyJWK`

```python
# jwt/api_jwk.py:37-40
if not algorithm and isinstance(self._jwk_data, dict):
    algorithm = self._jwk_data.get("alg", None)

if not algorithm:
    # Determine alg with kty (and crv).
```

* An explicit `algorithm=` argument wins.
* Otherwise the JWK's own `alg` is used **only if truthy**.
* Otherwise the code infers from `kty`/`crv` at `jwt/api_jwk.py:42-66`.

Note the `not algorithm` test is a truthiness test, not a type check, so `""`,
`0`, `False`, `{}` and `[]` all fall through to inference [source]. Compare
`alg=""` → `ES256` and `alg=0` → `ES256` [observed, O17].

The inference table is opinionated and lossy:

| `kty` | `crv` | inferred `alg` |
|---|---|---|
| `EC` | `P-256` **or absent** | `ES256` (`api_jwk.py:44`) |
| `EC` | `P-384` | `ES384` |
| `EC` | `P-521` | `ES512` |
| `EC` | `secp256k1` | `ES256K` |
| `RSA` | — | `RS256` |
| `oct` | — | `HS256` |
| `OKP` | `Ed25519` | `EdDSA` |
| `OKP` | `Ed448` | **rejected** (`api_jwk.py:64`) |

Two asymmetries matter for an explainable boundary:

* `RSA` without `alg` becomes `RS256`, so a PS256-only issuer whose JWKS omits
  `alg` cannot verify its own tokens [observed, O17/O18].
* `OKP`/`Ed448` is accepted when `alg=EdDSA` is stated but rejected when `alg`
  is omitted, even though `EdDSA` is exactly the algorithm the library would
  want to infer [observed, O17]. The same key material is usable or not
  depending on whether a redundant label is present.

### 2.2 The "skip unusable keys" pass erases the reason

```python
# jwt/api_jwk.py:150-165
for key in keys:
    if not isinstance(key, dict):
        # skip members that aren't JWK objects
        continue
    try:
        self.keys.append(PyJWK(key))
    except PyJWTError as error:
        if isinstance(error, MissingCryptographyError):
            raise error
        # skip unusable keys
        continue

if len(self.keys) == 0:
    raise PyJWKSetError(
        "The JWK Set did not contain any usable keys. Perhaps 'cryptography' is not installed?"
    )
```

Three distinct failure classes — **unsupported algorithm**, **corrupt key
material**, and **non-object member** — all converge on `continue`
[source]. Only `MissingCryptographyError` is re-raised. The residual error
message even guesses at the wrong cause ("Perhaps 'cryptography' is not
installed?"), which is misleading when `cryptography` *is* installed.

### 2.3 `__getitem__` and `match_kid` are both first-match with no policy

```python
# jwt/api_jwk.py:177-181
def __getitem__(self, kid: str) -> PyJWK:
    for key in self.keys:
        if key.key_id == kid:
            return key
    raise KeyError(f"keyset has no key for kid: {kid}")
```

```python
# jwt/jwks_client.py:328-331
for key in signing_keys:
    if key.key_id == kid:
        signing_key = key
        break
```

Neither consults `use`, `key_ops`, `alg`, or the token header. The client adds
a *separate* pre-filter:

```python
# jwt/jwks_client.py:252-256
signing_keys = [
    jwk_set_key
    for jwk_set_key in jwk_set.keys
    if jwk_set_key.public_key_use in ["sig", None] and jwk_set_key.key_id
]
```

So `PyJWKSet[...]` and `PyJWKClient.get_signing_key(...)` can select **different
entries for the same `kid`** [source]. Confirmed: with
`[use=enc alg=HS256, use=sig alg=HS512]` sharing a `kid`, `PyJWKSet["k"]` gives
the `enc`/`HS256` entry while the client gives the `sig`/`HS512` entry
[observed].

### 2.4 Verification is pinned to the selected key's algorithm

```python
# jwt/api_jws.py:408-430
if algorithms is None and isinstance(key, PyJWK):
    algorithms = [key.algorithm_name]
...
if not alg or (algorithms is not None and alg not in algorithms):
    raise InvalidAlgorithmError("The specified alg value is not allowed")

if isinstance(key, PyJWK):
    if alg != key.algorithm_name:
        raise InvalidAlgorithmError(
            f"Token algorithm {alg!r} does not match the key's "
            f"algorithm {key.algorithm_name!r}"
        )
    alg_obj = key.Algorithm
    prepared_key = alg_obj.prepare_key(key.key)
```

This is a genuine strengthening over a bare allow-list: the header cannot
select an algorithm the key is not bound to. Its consequence, though, is that
**the first-match selection becomes the algorithm policy**. A wrong first match
is not retried against the other duplicate.

### 2.5 `ECAlgorithm` validates the curve only at use time

`PyJWK.__init__` calls `self.Algorithm.from_jwk(...)`
(`jwt/api_jwk.py:83`), which for EC accepts any point that is valid *on the
curve named by `crv`* (`jwt/algorithms.py:858-893`). `_validate_curve`
(`jwt/algorithms.py:716-725`) is only reached through `prepare_key`, i.e. at
sign/verify. I confirmed this by spying on `_validate_curve`: **zero calls
during `PyJWK` construction, one call during `decode`** [observed].

So an entry labelled `alg=ES256` on P-384 material constructs fine, survives
`PyJWKSet`, is selectable by `kid`, and fails only when a token arrives.

---

## 3. Reproducible observations

Each ID is a section heading printed by the harness. Run:

```bash
PYTHONPATH=/srv/fb2/fangzhengmei/0093-pyjwt-5-1aaf313e \
  python3 -I -W ignore /tmp/jwks93/repro_jwks_selection.py
```

The `LocalClient` in the harness subclasses `PyJWKClient` and replaces only
`fetch_data()`, so all selection, filtering, caching and refresh logic under
test is the real implementation.

### 3.1 Input order decides the trust anchor (O1–O4)

Setup: two entries with the same `kid="dup"`, one P-256/`ES256`, one
RSA/`RS256`. Tokens are signed by each key.

| published order | `match_kid` picks | ES256 token | RS256 token |
|---|---|---|---|
| `[ES256, RS256]` | `ES256` | verifies | `InvalidAlgorithmError` |
| `[RS256, ES256]` | `RS256` | `InvalidAlgorithmError` | verifies |

[observed, O1] This is the core of the ambiguity: **the same JWKS content in a
different array order gives a different verification outcome**, and neither
outcome is "try the other duplicate".

`PyJWKSet["dup"]` shows the same first-match behaviour independently of the
client [observed, O2].

The skip pass changes *which* duplicate is reachable:

* First entry labelled `alg=ES999` (unsupported) → dropped, so the **second**
  entry wins and the RS256 token verifies [observed, O3].
* First entry labelled `alg=ES384` on P-256 material (constructs fine) →
  **kept**, so it wins and the RS256 token fails with no fallback
  [observed, O4].

So "unsupported algorithm" and "wrong-but-constructible key" are not just
differently reported — they produce **opposite selection results** for the same
key ordering.

### 3.2 Unsupported algorithm and corrupt material are indistinguishable (O5–O6)

Each member below was constructed alone and then placed alone in a set.

| member | `PyJWK(...)` | set containing only it |
|---|---|---|
| valid EC material, `alg=ES999` | `PyJWKError: Unable to find an algorithm for key` | `PyJWKSetError: ...did not contain any usable keys` |
| `kty=gOST` | `PyJWKError` | same `PyJWKSetError` |
| EC point not on P-256 | `InvalidKeyError: Invalid EC key` | same `PyJWKSetError` |
| P-256 coords 31 bytes | `InvalidKeyError: Coords should be 32 bytes` | same `PyJWKSetError` |
| unknown `crv=P-999` | `InvalidKeyError: Invalid curve` | same `PyJWKSetError` |
| RSA without `n` | `InvalidKeyError` | same `PyJWKSetError` |
| `oct` labelled `RS256` | `InvalidKeyError: Not an RSA key` | same `PyJWKSetError` |
| EC labelled `HS256` | `InvalidKeyError: Not an HMAC key` | same `PyJWKSetError` |

[observed, O5] At `PyJWK` level the messages are informative and the exception
*types* separate "no such algorithm" (`PyJWKError`) from "bad material"
(`InvalidKeyError`). At `PyJWKSet` level that distinction is **completely
lost** — every one collapses into the single "no usable keys" message. A
JWKS author or operator cannot tell from the outside whether their set was
rejected for an unsupported algorithm or a broken point.

With one good key present, the bad entries vanish from `keys` and the client
returns only the good `kid` [observed, O6]. That is the intended resilience
behaviour, but it is indistinguishable from "the issuer never published that
key".

### 3.3 Members that are not `PyJWTError` abort the entire set (O7)

The `except PyJWTError` at `jwt/api_jwk.py:156` is narrower than the set of
things `PyJWK` can raise:

| member | raised | escapes `PyJWKSet`? |
|---|---|---|
| `alg="none"` | `NotImplementedError` | **yes — aborts whole set** |
| `alg={"x":1}` | `TypeError: unhashable type: 'dict'` | **yes** |
| `alg=["ES256"]` | `TypeError: unhashable type: 'list'` | **yes** |

[observed, O7] `alg="none"` reaches `get_default_algorithms()["none"]` →
`NoneAlgorithm`, whose `from_jwk` raises bare `NotImplementedError`
(`jwt/algorithms.py:310`), which is not a `PyJWTError`. The unhashable values
fail at the `self._algorithms[algorithm]` dict lookup
(`jwt/api_jwk.py:76`) before any exception wrapping.

Consequence, confirmed end-to-end through the client: a JWKS containing **one**
`alg="none"` member plus a perfectly valid signing key makes
`get_signing_key("usable")` raise `NotImplementedError` for *every* caller
[observed, O7]. This contradicts the deliberate resilience rule in §2.2 ("a
single bad entry no longer fails an otherwise usable JWK Set", CHANGELOG
v2.15.0). The rule holds for `PyJWTError` subclasses only.

This also matters for the `alg` field's declared type. RFC 7517 §4.4 says `alg`
is a string; nothing in `PyJWK` enforces that, so a hostile or buggy endpoint
can choose between "silently skipped" (`"ES999"`), "silently inferred"
(`""`, `0`, `False`), and "kills the set" (`"none"`, `{}`, `[]`) purely by
picking the JSON type of one field [observed, O17/O7].

### 3.4 `alg`/`crv` disagreement survives construction (O8–O9)

P-384 material labelled `alg=ES256`:

* `PyJWK` constructs successfully; `algorithm_name == "ES256"`, expected curve
  `secp256r1`, actual curve `secp384r1` [observed, O8].
* `PyJWKSet` keeps it [observed, O8].
* An ES384 token fails with `InvalidAlgorithmError` — either the allow-list
  gate or the explicit alg-mismatch branch, never a curve error, because the
  algorithm check runs first [observed, O8].
* With `algorithms=["ES384"]` forced, the message becomes
  `Token algorithm 'ES384' does not match the key's algorithm 'ES256'` — which
  points at the `alg` label and conceals that the *curve* is also wrong.

P-256 material labelled `alg=ES384` (the mirror case): constructs, and fails at
verify with `InvalidKeyError: The key's curve 'secp256r1' does not match the
expected curve 'secp384r1'` [observed, O9].

The observable difference matters for diagnosis: an operator seeing
"alg does not match the key's algorithm" will look at the `alg` field, when the
underlying defect may be `crv`. Nothing in the message chain correlates the two
fields at construction time.

### 3.5 `use` is case-sensitive, client-only, and not a trust boundary (O10–O11)

| `use` value | client `get_signing_keys()` | `PyJWKSet` keeps it |
|---|---|---|
| `"sig"` | selected | yes |
| `None` | selected | yes |
| `"SIG"`, `"Sig"`, `"sign"`, `"verify"`, `""` | `PyJWKClientError: ...did not contain any signing keys` | yes |
| `"enc"` | excluded | **yes** |

[observed, O10] The equality check is
`public_key_use in ["sig", None]` (`jwt/jwks_client.py:255`) — exact string
match. A JWKS that emits `use: "SIG"` (or omits the lowercase convention)
produces a client error indistinguishable from an empty endpoint.

More importantly, `use` is **not** a security boundary. A `use="enc"` entry is
retained by `PyJWKSet` and is fully usable for signature verification when
reached through `PyJWKSet[kid]` [observed, O11]:

```
PyJWKSet['k'].public_key_use  -> 'enc'
decode ES256 token via PyJWKSet['k'] -> {'x': 1}
```

Anyone wiring `jwt.decode(token, key=jwk_set[kid], ...)` — a natural pattern —
bypasses the `use` filter entirely.

`key_ops` is never read anywhere in the selection path [source]. A member with
`key_ops: ["encrypt"]` and no `use` is returned by the client as a signing key
[observed, O12]. RFC 7517 §4.3 says `key_ops` and `use` SHOULD NOT be used
together and that when present they should agree; PyJWT honours `use` partially
and `key_ops` not at all.

### 3.6 `kid` filtering and equality semantics (O12–O13)

`and jwk_set_key.key_id` (`jwt/jwks_client.py:255`) is a *truthiness* test.
`kid: ""`, `kid: 0`, and a missing `kid` are all dropped by the client, while
`PyJWKSet` retains `"", 0, None` [observed, O12]. A JWKS-only-with-`kid=0`
therefore yields `PyJWKClientError: ...did not contain any signing keys`, not a
lookup failure.

`match_kid` uses Python `==`. Since `1 == True`, an entry with `kid: true`
matches a token asking for `kid: 1` and vice versa [observed, O13]:

```
stored kid=1     lookup(True)  -> 1        (matched)
stored kid=True  lookup(1)     -> True     (matched)
stored kid=1     lookup("1")   -> PyJWKClientError
```

Token-side `kid` is type-checked (`jwt/api_jws.py:459-461` requires `str`), so
`get_signing_key_from_jwt` rejects non-string `kid` in the token header with
`InvalidTokenError` [observed]. But the JWKS side is unvalidated, and
`PyJWKSet.__getitem__` inherits the same `==` loose match.

### 3.7 Rotation: distinct `kid`s work; a reused `kid` is unresolvable (O14–O16)

* Two keys under different `kid`s (`old`, `new`) both verify correctly
  [observed, O14]. This is the supported rotation path.
* Two keys under the **same** `kid` with different algorithms: the first is
  picked, the token signed by the second fails with `InvalidAlgorithmError`,
  and **no refresh occurs** because `match_kid` found a `kid` match
  [observed, O14].
* Two keys under the same `kid` with the *same* algorithm but different
  material: the first is picked and the second's token fails with
  `InvalidSignatureError` [observed, O24] — the case that most resembles a
  mid-rotation overlap, and the easiest to mistake for "the issuer signed with
  a key we do not have":

  ```
  picked material == first entry: True
  token signed by first entry  -> {'x': 1}
  token signed by second entry !! InvalidSignatureError: Signature verification failed
  fetches (kid matched both times): 1
  ```

Refresh is triggered **only** by a `kid` miss, never by a verification failure
[source: `jwt/jwks_client.py:281-296`; observed, O15]:

```
picked ES256; fetches=1
verification -> InvalidAlgorithmError; fetches=1     # no retry
unknown kid  -> PyJWKClientError;      fetches=2     # refresh
```

Tier-2 caching (`cache_keys=True`) is an unbounded-in-time LRU keyed only by
`kid` (`jwt/jwks_client.py:141-145`). Once the first answer is cached it is
returned for the process lifetime even after the endpoint rotates to different
material under the same `kid` [observed, O16]:

```
first=ES256 second=ES256 same_object=True fetches=1
rotated token via cached client -> InvalidAlgorithmError
rotated token via fresh  client -> {'x': 1}
```

### 3.8 An all-unusable JWKS escapes the client error contract (O19)

`PyJWKSetError` is a `PyJWTError` but **not** a `PyJWKClientError`
(`jwt/exceptions.py`). `PyJWKClient.get_jwk_set()` does not translate it
[source: `jwt/jwks_client.py:216`, `223`]. Observed [O19]:

```
LocalClient.get_jwk_set()      !! PyJWKSetError: The JWK Set did not contain any usable keys...
LocalClient.get_signing_keys() !! PyJWKSetError: ...same...
```

A caller written as `except PyJWKClientError:` around the documented client
surface (`get_jwk_set`, `get_signing_keys`, `get_signing_key`) will not catch
this. The client's own docstrings advertise `PyJWKClientError` for these
methods (`jwt/jwks_client.py:245`, `274`).

A related amplification. The "unknown `kid` → cooldown, then one forced
refresh" protection is implemented *inside* `get_signing_key` and only runs
after `get_signing_keys()` has returned a usable list
(`jwt/jwks_client.py:278-296`). An all-unusable set makes `get_signing_keys()`
itself raise `PyJWKSetError`, so the call never reaches the cooldown check at
line 281. Two sub-cases, both measured with `cooldown_duration=300` and four
lookups → **4 network fetches** [observed]:

* `cache_jwk_set=True`: `fetch_data()` populates the cache at
  `jwt/jwks_client.py:186`, i.e. *before* it records
  `_last_successful_fetch` at line 187. `put()` raises `PyJWKSetError` from
  `jwt/api_jwk.py:163`, so the timestamp is never set **and** the cache is never
  populated — every subsequent lookup is a cache miss and re-fetches.
* `cache_jwk_set=False`: no cache exists, so every lookup fetches regardless;
  `_last_successful_fetch` *is* set, but the cooldown check is unreachable for
  the reason above.

Control: a valid set with an unknown `kid` performs **1** fetch for the same
four lookups, because that path does reach the cooldown. So a persistently
broken JWKS turns every presented token into one outbound request, while the
cooldown that was designed to prevent exactly that never engages.

### 3.9 Key length and `alg="none"` (O20–O21 and direct probes)

* Minimum key length is checked at sign/verify
  (`jwt/api_jws.py:438-443`), never during selection. A 1024-bit RSA key and a
  4-byte HMAC secret are both selected by the client without comment
  [observed, O20]. Default behaviour is a warning;
  `enforce_minimum_key_length: True` turns it into `InvalidKeyError`.
* `alg="none"` is a registered algorithm in `get_default_algorithms()`
  (`jwt/algorithms.py:147`) whose `verify` always returns `False`
  (`jwt/algorithms.py:302-303`). So even if a `none`-labelled JWK were
  constructible, it could not verify anything; it fails with
  `InvalidSignatureError`, never a silent accept [observed]. The danger of
  `alg="none"` in a JWKS is therefore **denial of the whole set** (§3.3), not
  signature bypass.

### 3.10 The refusal taxonomy a caller actually sees (O21–O22)

Five distinct conditions produce four different, non-overlapping messages:

| condition | exception | message |
|---|---|---|
| header has no `alg` | `InvalidAlgorithmError` | `Algorithm not specified` |
| header `alg` falsy (`""`) | `InvalidAlgorithmError` | `The specified alg value is not allowed` |
| header `alg` not in allow-list | `InvalidAlgorithmError` | `The specified alg value is not allowed` |
| header `alg` unknown to the library, raw key | `InvalidAlgorithmError` | `Algorithm not supported` |
| selected `PyJWK`'s alg ≠ header alg | `InvalidAlgorithmError` | `Token algorithm 'X' does not match the key's algorithm 'Y'` |
| header `alg` unknown, `PyJWK` supplied, no allow-list | `InvalidAlgorithmError` | `The specified alg value is not allowed` |

[observed, O21] Two of these collapse to the same string (falsy `alg` and
`alg not in allow-list`), and the always-present `PyJWK` branch means the
"Algorithm not supported" message — the one that actually means *unsupported
algorithm* — is **unreachable** when a `PyJWK` is passed. In the JWKS flow a
`PyJWK` is always what you have, so callers can never distinguish "the issuer
asked for an algorithm PyJWT does not implement" from "the caller's allow-list
did not include it". This is the reporting half of the ambiguity in §3.2.

A separate, pre-existing sharp edge: `algorithms` is typed
`Sequence[str] | None` but is used as `alg not in algorithms`
(`jwt/api_jws.py:415`). Passing a bare `str` makes the check a **substring**
test. `algorithms="ES256K"` admits an `ES256` token because `"ES256" in
"ES256K"` [observed, O22]:

```
algorithms='ES256'   -> ACCEPTED
algorithms='ES256K'  -> ACCEPTED          # substring, not membership
algorithms=['ES256K'] -> InvalidAlgorithmError   # correct
```

It is masked when the `PyJWS` registry was constructed with an
`algorithms=` filter (`jwt/api_jws.py:45-52`), because the registry no longer
contains the narrower name — but the module-level `jwt.decode` uses an
unfiltered global registry (`jwt/api_jws.py:478`), so the substring behaviour
is live for the most common entry point. Non-string header `alg` combined with
a bare-string allow-list raises a bare `TypeError: 'in <string>' requires string
as left operand` instead of a `PyJWTError`.

### 3.11 Container-level normalization gaps (O23)

`PyJWKSet.from_dict` is typed `dict[str, Any]` but does not check
(`jwt/api_jwk.py:168-170`):

| input | result |
|---|---|
| `from_dict(None)` | `AttributeError: 'NoneType' object has no attribute 'get'` |
| `from_json("null")` | `AttributeError` (same) |
| `{"keys": "abcd"}` | `PyJWKSetError: Invalid JWK Set value` |
| `{"keys": {}}` | `PyJWKSetError: The JWK Set did not contain any keys` |
| `{"keys": [None, None]}` | `PyJWKSetError: ...no usable keys` |
| duplicate identical entries | both kept |

[observed, O23] `PyJWKClient` guards the top-level payload shape
(`_as_jwk_set_payload`, `jwt/jwks_client.py:227-232`), so the `AttributeError`
is reachable only for direct `PyJWKSet` users — but it is a `PyJWTError`
contract violation on a documented public class.

Note also that `PyJWKSet` performs **no de-duplication**. Two byte-identical
entries with the same `kid` both survive, and `len(keys) == 2`. Any downstream
`len()`-based or `set`-based assumption about `kid`s is unsafe.

---

## 4. Minimal differences that separate the cases

These are the smallest changes that flip the outcome, which is what makes the
boundary explainable (or not):

| change to the JWKS | outcome change | ID |
|---|---|---|
| swap two array entries with equal `kid` | verifies ↔ `InvalidAlgorithmError` | O1 |
| change first duplicate's `alg` from `"ES999"` to `"ES384"` | second duplicate reachable ↔ first duplicate wins | O3/O4 |
| change `alg` from `"ES999"` to absent | skipped ↔ inferred `RS256`/`ES256` | O5/O17 |
| change `alg` from `""` to `"ES256"` | inferred ↔ explicit (same result here) | O17 |
| change `alg` from `"none"` to `"ES999"` | whole set aborts ↔ member skipped | O7/O5 |
| change `alg` from `"ES999"` to `{}` | member skipped ↔ whole set aborts | O5/O7 |
| change `use` from `"sig"` to `"SIG"` | selected ↔ client error (empty GWKS) | O10 |
| change `use` from `"sig"` to `"enc"` | client excludes ↔ `PyJWKSet` still selects | O11 |
| change `kid` from `1` to `"1"` | matches `True` ↔ does not match | O13 |
| change `crv` from `P-256` to `P-384`, keep `alg=ES256` | constructs+verifies path ↔ constructs, fails at verify | O8 |
| add a second entry under the same `kid` | single trust anchor ↔ order-dependent anchor | O1/O14 |
| rotate material under the same `kid` with `cache_keys=True` | new key used ↔ stale key used | O16 |

The first two rows are the sharpest: **a purely cosmetic reordering or a
one-character algorithm label decides whether a token verifies.** No logging,
no warning, and no returned metadata distinguishes the two outcomes other than
a coarse `InvalidAlgorithmError`.

---

## 5. Where the trust boundary actually is

Stated as rules the current code implements, not as recommendations:

1. **Only entries that construct are candidates.** Construction means
   "`alg` maps to a known algorithm *and* the key material parses *and*, if
   `alg` was explicit, the material matches that algorithm's `kty`". It does
   **not** mean the `crv` agrees with `alg`, and it does not mean the key is
   the right one for the issuer.
2. **Among candidates, position wins.** `PyJWKSet` preserves input order;
   `__getitem__` and `match_kid` both `break` on the first `==` match. There is
   no scoring, no `use` preference, no `alg` preference, and no retry.
3. **Only the client applies `use`/`kid` presence, and only for its own
   lookups.** `PyJWKSet` remains a fully permissive index.
4. **The selected entry's `alg` label is the algorithm policy.** The header can
   only narrow it, never widen it (`jwt/api_jws.py:424`). But the label can be
   wrong relative to `crv` or relative to the token actually issued.
5. **Failure to select is silence or a set-level error.** A bad member
   disappears (if `PyJWTError`), or takes the set down (if not), or triggers a
   refresh loop (if the whole set is unusable). None of these report *which*
   member and *why*.

The practical consequence: the trust boundary is **the JSON array order of the
first constructible key bearing a matching `kid`**, with `use` as an advisory
filter that applies on one of two lookup paths. That is not an explainable
boundary, and no API surface exposes the decision that was made.

---

## 6. Verification gaps (what the repository does not test)

I ran the existing suites as a baseline: `tests/test_api_jwk.py` and
`tests/test_jwks_client.py` → **72 passed, 3 skipped** (skips are the
`no_crypto_required` cases, as `cryptography` is installed here).

Grepping the test tree, the following are unpinned:

| behaviour | current coverage | gap |
|---|---|---|
| Duplicate `kid` of any kind | **none** — the only "duplicate" hit is `test_register_algo_does_not_allow_duplicate_registration` (`tests/test_api_jws.py:51`), unrelated | **No test** asserts first-match semantics, order sensitivity, or the absence of fallback. Rows O1–O4 are entirely untested. |
| `alg="none"` inside a JWKS | **none** in `test_api_jwk.py` / `test_jwks_client.py` | The whole-set abort (§3.3) is untested and unprotected against regression. |
| Non-hashable / non-string `alg` | **none** | The `TypeError` escape at O7 is untested. |
| `use` case sensitivity (`"SIG"`, `"sign"`) | **none** | O10 is untested; only exact `"sig"`/`"enc"`/absent appear (`test_jwks_client.py:230-256`). |
| `use="enc"` reachable via `PyJWKSet` for verification | **none** | O11 is untested; existing tests assert `public_key_use` *value* but never that an `enc` key verifies. |
| `key_ops` | **none in the JWK/JWKS path** — only in `to_jwk` round-trip assertions (`tests/test_algorithms.py:742,771`) | O12 is untested. |
| Falsy `kid` (`""`, `0`, `None`) | **none** | O12 is untested. |
| `kid` type coercion (`1` vs `True` vs `"1"`) | **none** | O13 is untested. |
| `alg`/`crv` disagreement on JWK construction | **partial** — curve validation is tested at `prepare_key` (`tests/test_algorithms.py:1573-1645`) but **never** through `PyJWK`/`PyJWKSet` | O8/O9 are untested; nothing asserts that construction succeeds and only verification fails. |
| `alg` omitted → inferred algorithm | covered for a few cases (`test_should_load_key_without_alg_from_dict`, `test_should_load_key_hmac_without_alg_from_dict`, `test_should_load_key_okp_without_alg_from_dict`) | **No** coverage of `RSA→RS256` vs `PS256` consequences (O18), `Ed448` rejected-without-`alg` but accepted-with (O17), or falsy `alg` (`""`, `0`) falling through to inference. |
| All-unusable JWKS raising `PyJWKSetError` (not `PyJWKClientError`) from the client | **none** | O19 is untested; `test_keyset_with_unknown_alg` covers `PyJWKSet` directly, not through `PyJWKClient`. |
| Refresh-loop amplification on an all-unusable endpoint | **none** | The cooldown tests (`test_unknown_kid_refresh_*`) all use a *valid* set with a missing `kid`, so they never exercise the unreachable-cooldown path in §3.8. |
| `algorithms` passed as a bare `str` | **none** — every call site passes a list | O22's substring behaviour and the `TypeError` on non-string header `alg` are untested. |
| `PyJWKSet.from_dict(None)` / `from_json("null")` | **none** | O23's `AttributeError` is untested. |
| Reused `kid` across rotation, and `cache_keys=True` staleness | **none** | O14/O16/O24 are untested; `test_get_signing_key_caches_result` only proves the cache hits, not that it can go stale. |

Additional gaps that are structural rather than test-shaped:

* **[gap] No observability.** Neither `PyJWKSet` nor `PyJWKClient` exposes
  which members were dropped or why. `PyJWKSet.keys` contains survivors only;
  the discarded `PyJWKError`/`InvalidKeyError` instances are dropped on the
  floor at `jwt/api_jwk.py:156-160`. There is no way to write a test that
  asserts *why* a member was excluded, because the information is not retained.
* **[gap] Exception contract mismatch.** `PyJWKSetError` not deriving from
  `PyJWKClientError` means the documented `:raises PyJWKClientError:` on
  `get_jwk_set`/`get_signing_keys`/`get_signing_key`
  (`jwt/jwks_client.py:198`, `245`, `274`) is inaccurate for the
  all-unusable-set case. No test asserts the documented type.
* **[gap] RFC conformance is not asserted.** Nothing checks that `alg` is a
  string (RFC 7517 §4.4), that `use` and `key_ops` are consistent (§4.3), or
  that duplicate `kid`s are rejected. These are exactly the inputs that drive
  the order-dependent selection.
* **[gap] No differential test across array orderings.** Several behaviours
  here (O1, O3/O4) are only visible when the *same* set is presented in two
  orders. The suite has no parametrisation over order, and `reversed` /
  ordering-based tests are absent from both JWK test files.

---

## 7. Reproduction inventory

| file | purpose |
|---|---|
| `/tmp/jwks93/repro_jwks_selection.py` | consolidated harness; prints sections O1–O24 |
| `/tmp/jwks93/repro.py`, `probe2.py`, `probe3.py`, `probe4.py`, `probe5.py` | earlier exploratory rounds, superseded by the consolidated script |
| `/tmp/jwks93/final_out.txt` | captured output of the consolidated run in this environment |

All fixtures are generated at import time; no key material is persisted and no
network access occurs. `LocalClient` overrides only `fetch_data()`, so the
selection, filtering, caching, cooldown and refresh logic exercised is
unmodified repository code.

Because the harness lives outside the repository, Appendix A carries a
self-contained excerpt for the two order-sensitivity results (O1, O3/O4), which
are the central claims. It reproduces from a clean checkout with no scratch
files.

---

## Appendix A — self-contained repro for the order-dependence claim

Run from the repository root:

```bash
python3 -I -W ignore - <<'PY'
import json, sys
sys.path.insert(0, ".")
import jwt
from jwt.algorithms import ECAlgorithm, RSAAlgorithm
from jwt.api_jwk import PyJWKSet
from cryptography.hazmat.primitives.asymmetric import ec, rsa

ec_k = ec.generate_private_key(ec.SECP256R1())
EC = json.loads(ECAlgorithm.to_jwk(ec_k.public_key()))
rsa_k = rsa.generate_private_key(public_exponent=65537, key_size=2048)
RSA = json.loads(RSAAlgorithm.to_jwk(rsa_k.public_key()))

ec_entry = {**EC, "kid": "dup", "alg": "ES256", "use": "sig"}
rs_entry = {**RSA, "kid": "dup", "alg": "RS256", "use": "sig"}
tok = jwt.encode({"sub": "a"}, rsa_k, algorithm="RS256", headers={"kid": "dup"})

for name, keys in (("[ES256, RS256]", [ec_entry, rs_entry]),
                   ("[RS256, ES256]", [rs_entry, ec_entry])):
    picked = PyJWKSet.from_dict({"keys": keys})["dup"]
    try:
        jwt.decode(tok, picked, options={"verify_exp": False})
        result = "VERIFIES"
    except jwt.PyJWTError as exc:
        result = f"{type(exc).__name__}: {exc}"
    print(f"{name} -> picked {picked.algorithm_name}: {result}")

# Swap the first entry's alg from an unsupported one to a constructible one:
# the set's selection flips from 'second entry wins' to 'first entry wins'.
bad = {**ec_entry, "alg": "ES999"}
wrong = {**ec_entry, "alg": "ES384"}
print("first entry alg=ES999 ->", PyJWKSet.from_dict(
    {"keys": [bad, rs_entry]})["dup"].algorithm_name)
print("first entry alg=ES384 ->", PyJWKSet.from_dict(
    {"keys": [wrong, rs_entry]})["dup"].algorithm_name)
PY
```

Expected output in this environment:

```
[ES256, RS256] -> picked ES256: InvalidAlgorithmError: The specified alg value is not allowed
[RS256, ES256] -> picked RS256: VERIFIES
first entry alg=ES999 -> RS256
first entry alg=ES384 -> ES384
```

The first two lines show that **reordering two entries with the same `kid`
decides whether the token verifies**. The last two show that the *only*
difference between "the second duplicate is reachable" and "the first duplicate
shadows it" is whether the first entry's `alg` label happens to be unsupported
or merely wrong.
