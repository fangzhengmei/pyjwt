"""
Consistency tests for compact-JWT parsing and signature verification.

The property under test: the exact bytes covered by the signature are the
bytes whose header parameters drive verification decisions and whose payload
claims the application reads. Finite mutations of the three encoded segments,
duplicate header fields, critical (``crit``) extensions, and detached
(``b64=false``) payloads must either round-trip losslessly or be rejected
with the precise exception category -- never silently reinterpreted, and
never such that one payload passes signature verification while a different
payload reaches claim parsing.
"""

import hashlib
import hmac
import json

import pytest

from jwt import PyJWT
from jwt.api_jws import PyJWS
from jwt.exceptions import (
    DecodeError,
    InvalidAlgorithmError,
    InvalidSignatureError,
    InvalidTokenError,
)
from jwt.utils import base64url_decode, base64url_encode

# 256-bit secret so no InsecureKeyLengthWarning is emitted for HS256.
SECRET = "0123456789abcdef0123456789abcdef"
ALGORITHMS = ["HS256"]

_B64URL_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"


def sign_hs256(signing_input: bytes, secret: str = SECRET) -> bytes:
    return hmac.new(secret.encode(), signing_input, hashlib.sha256).digest()


def make_token(
    header_json: bytes,
    payload_segment: bytes,
    *,
    signing_input: bytes | None = None,
    signature_segment: bytes | None = None,
) -> str:
    """Hand-assemble a compact token from raw parts.

    ``signing_input`` defaults to ``header.payload`` as transmitted; pass an
    explicit value to sign bytes that differ from the transmitted segments.
    """
    header_segment = base64url_encode(header_json)
    if signing_input is None:
        signing_input = b".".join([header_segment, payload_segment])
    if signature_segment is None:
        signature_segment = base64url_encode(sign_hs256(signing_input))
    return b".".join([header_segment, payload_segment, signature_segment]).decode()


def noncanonical_variant(segment: bytes) -> bytes:
    """Return a different base64url spelling that decodes to the same bytes.

    The last character of a canonical segment may carry unused low bits;
    flipping one yields a segment that base64-decodes to identical bytes but
    is not the canonical re-encoding of those bytes.
    """
    decoded = base64url_decode(segment)
    assert base64url_encode(decoded) == segment, "start from a canonical segment"
    assert len(decoded) % 3 != 0, "no unused bits to flip; pick another input"
    last_index = _B64URL_ALPHABET.index(chr(segment[-1]))
    variant = segment[:-1] + _B64URL_ALPHABET[last_index ^ 1].encode()
    assert base64url_decode(variant) == decoded
    assert base64url_encode(decoded) != variant
    return variant


@pytest.fixture
def jws() -> PyJWS:
    return PyJWS()


@pytest.fixture
def jwt() -> PyJWT:
    return PyJWT()


# Header/payload JSON chosen so each base64url segment has unused trailing
# bits (decoded length not a multiple of 3), enabling non-canonical variants.
HEADER_JSON = b'{"alg":"HS256","typ":"JWT","kid":"1"}'
PAYLOAD_JSON = b'{"sub":"alice1"}'


class TestSegmentEncodingMutations:
    """Finite mutations of each of the three compact segments."""

    def test_valid_token_roundtrips_exact_claims(self, jwt: PyJWT) -> None:
        token = make_token(HEADER_JSON, base64url_encode(PAYLOAD_JSON))
        assert jwt.decode(token, SECRET, algorithms=ALGORITHMS) == {"sub": "alice1"}

    @pytest.mark.parametrize("segment_index", [0, 1, 2])
    def test_noncanonical_segment_rejected_before_any_claim_parsing(
        self, jwt: PyJWT, segment_index: int
    ) -> None:
        # A segment that decodes to the intended bytes but is spelled
        # non-canonically must be rejected as a DecodeError -- even though
        # the decoded content is unchanged -- so that the verified bytes and
        # the parsed bytes can never diverge.
        token = make_token(HEADER_JSON, base64url_encode(PAYLOAD_JSON))
        segments = token.split(".")
        segments[segment_index] = noncanonical_variant(
            segments[segment_index].encode()
        ).decode()
        with pytest.raises(DecodeError) as exc_info:
            jwt.decode(".".join(segments), SECRET, algorithms=ALGORITHMS)
        assert type(exc_info.value) is DecodeError

    @pytest.mark.parametrize("segment_index", [0, 1])
    def test_noncanonical_segment_rejected_even_with_valid_signature(
        self, jws: PyJWS, segment_index: int
    ) -> None:
        # Stronger form: the attacker re-signs so the signature is valid for
        # the non-canonical spelling of the signed portion (header/payload).
        # The canonical-encoding invariant must still reject the token,
        # otherwise a non-canonical payload could pass verification while
        # canonical bytes reach the application.
        token = make_token(HEADER_JSON, base64url_encode(PAYLOAD_JSON))
        segments = token.split(".")
        segments[segment_index] = noncanonical_variant(
            segments[segment_index].encode()
        ).decode()
        signing_input = ".".join(segments[:2]).encode()
        segments[2] = base64url_encode(sign_hs256(signing_input)).decode()
        with pytest.raises(DecodeError) as exc_info:
            jws.decode(".".join(segments), SECRET, algorithms=ALGORITHMS)
        assert type(exc_info.value) is DecodeError

    @pytest.mark.parametrize("segment_index", [0, 1, 2])
    def test_invalid_alphabet_characters_rejected(
        self, jws: PyJWS, segment_index: int
    ) -> None:
        token = make_token(HEADER_JSON, base64url_encode(PAYLOAD_JSON))
        segments = token.split(".")
        segments[segment_index] = segments[segment_index][:4] + "!!!!"
        with pytest.raises(DecodeError) as exc_info:
            jws.decode(".".join(segments), SECRET, algorithms=ALGORITHMS)
        assert type(exc_info.value) is DecodeError

    @pytest.mark.parametrize("segment_index", [0, 1, 2])
    def test_excessive_padding_rejected(self, jws: PyJWS, segment_index: int) -> None:
        token = make_token(HEADER_JSON, base64url_encode(PAYLOAD_JSON))
        segments = token.split(".")
        segments[segment_index] = segments[segment_index] + "==="
        with pytest.raises(DecodeError) as exc_info:
            jws.decode(".".join(segments), SECRET, algorithms=ALGORITHMS)
        assert type(exc_info.value) is DecodeError

    def test_legally_padded_segments_roundtrip(self, jwt: PyJWT) -> None:
        # ALB-style: segments carry trailing '=' and the signature covers the
        # padded spelling as transmitted. This is legal and must decode to
        # the exact claims.
        def pad(segment: bytes) -> bytes:
            return segment + b"=" * (-len(segment) % 4)

        header_segment = pad(base64url_encode(HEADER_JSON))
        payload_segment = pad(base64url_encode(PAYLOAD_JSON))
        assert header_segment.endswith(b"=")
        assert payload_segment.endswith(b"=")
        signing_input = b".".join([header_segment, payload_segment])
        signature_segment = pad(base64url_encode(sign_hs256(signing_input)))
        token = b".".join([header_segment, payload_segment, signature_segment])
        assert jwt.decode(token.decode(), SECRET, algorithms=ALGORITHMS) == {
            "sub": "alice1"
        }

    def test_padding_added_after_signing_fails_verification(
        self, jwt: PyJWT
    ) -> None:
        # Re-spelling a segment (here: legal-looking padding) without
        # re-signing changes the verified bytes, so the signature -- not the
        # claims -- is what fails.
        payload_json = b'{"sub":"a"}'
        payload_segment = base64url_encode(payload_json)
        assert len(payload_segment) % 4 == 3, "one '=' pad stays well-formed"
        token = make_token(HEADER_JSON, payload_segment)
        segments = token.split(".")
        segments[1] += "="
        with pytest.raises(InvalidSignatureError) as exc_info:
            jwt.decode(".".join(segments), SECRET, algorithms=ALGORITHMS)
        assert type(exc_info.value) is InvalidSignatureError


class TestDuplicateHeaderFields:
    """JSON objects with repeated member names: the parsed (last) value is
    what both verification and the application observe -- assert they agree."""

    def test_duplicate_alg_effective_value_is_used_for_verification(
        self, jws: PyJWS
    ) -> None:
        # json.loads keeps the last "alg". Verification must select HS256
        # (the value the application also reads back), not the first one.
        header_json = b'{"alg":"none","typ":"JWT","alg":"HS256"}'
        token = make_token(header_json, base64url_encode(PAYLOAD_JSON))
        decoded = jws.decode_complete(token, SECRET, algorithms=ALGORITHMS)
        assert decoded["header"]["alg"] == "HS256"
        assert decoded["payload"] == PAYLOAD_JSON

    def test_duplicate_alg_disallowed_effective_value_rejected(
        self, jws: PyJWS
    ) -> None:
        # The effective (last) alg is "none"; it must not be silently
        # overridden by the earlier HS256 entry nor ignored.
        header_json = b'{"alg":"HS256","typ":"JWT","alg":"none"}'
        token = make_token(header_json, base64url_encode(PAYLOAD_JSON))
        with pytest.raises(InvalidAlgorithmError) as exc_info:
            jws.decode(token, SECRET, algorithms=ALGORITHMS)
        assert type(exc_info.value) is InvalidAlgorithmError

    def test_duplicate_payload_claims_last_wins_over_verified_bytes(
        self, jwt: PyJWT
    ) -> None:
        # The signature covers the raw duplicate-containing JSON; the
        # application must read exactly the last value of that signed text.
        payload_json = b'{"sub":"first","sub":"second"}'
        token = make_token(HEADER_JSON, base64url_encode(payload_json))
        assert jwt.decode(token, SECRET, algorithms=ALGORITHMS) == {"sub": "second"}


class TestCriticalExtensions:
    """Unsupported critical semantics must never be silently ignored."""

    def _signed_token_with_header(self, header: dict) -> str:
        header_json = json.dumps(header, separators=(",", ":")).encode()
        return make_token(header_json, base64url_encode(PAYLOAD_JSON))

    def test_unknown_crit_extension_rejected_despite_valid_signature(
        self, jws: PyJWS
    ) -> None:
        token = self._signed_token_with_header(
            {"alg": "HS256", "typ": "JWT", "crit": ["unknownExt"], "unknownExt": True}
        )
        with pytest.raises(InvalidTokenError) as exc_info:
            jws.decode(token, SECRET, algorithms=ALGORITHMS)
        assert type(exc_info.value) is InvalidTokenError
        assert "Unsupported critical extension" in str(exc_info.value)

    def test_crit_naming_registered_claim_rejected(self, jws: PyJWS) -> None:
        # "exp" is a registered claim, not an extension PyJWT understands as
        # critical; listing it in crit must not be silently ignored.
        token = self._signed_token_with_header(
            {"alg": "HS256", "typ": "JWT", "crit": ["exp"], "exp": 9999999999}
        )
        with pytest.raises(InvalidTokenError) as exc_info:
            jws.decode(token, SECRET, algorithms=ALGORITHMS)
        assert type(exc_info.value) is InvalidTokenError

    def test_crit_not_a_list_rejected(self, jws: PyJWS) -> None:
        token = self._signed_token_with_header(
            {"alg": "HS256", "typ": "JWT", "crit": "b64"}
        )
        with pytest.raises(InvalidTokenError) as exc_info:
            jws.decode(token, SECRET, algorithms=ALGORITHMS)
        assert type(exc_info.value) is InvalidTokenError

    def test_crit_empty_list_rejected(self, jws: PyJWS) -> None:
        token = self._signed_token_with_header(
            {"alg": "HS256", "typ": "JWT", "crit": []}
        )
        with pytest.raises(InvalidTokenError) as exc_info:
            jws.decode(token, SECRET, algorithms=ALGORITHMS)
        assert type(exc_info.value) is InvalidTokenError

    def test_crit_non_string_entry_rejected(self, jws: PyJWS) -> None:
        token = self._signed_token_with_header(
            {"alg": "HS256", "typ": "JWT", "crit": [42]}
        )
        with pytest.raises(InvalidTokenError) as exc_info:
            jws.decode(token, SECRET, algorithms=ALGORITHMS)
        assert type(exc_info.value) is InvalidTokenError

    def test_crit_b64_without_b64_header_rejected(self, jws: PyJWS) -> None:
        token = self._signed_token_with_header(
            {"alg": "HS256", "typ": "JWT", "crit": ["b64"]}
        )
        with pytest.raises(InvalidTokenError) as exc_info:
            jws.decode(token, SECRET, algorithms=ALGORITHMS)
        assert type(exc_info.value) is InvalidTokenError
        assert "missing" in str(exc_info.value)

    def test_b64_false_without_crit_rejected(self, jws: PyJWS) -> None:
        # RFC 7797 §3: b64=false MUST be declared critical; a valid
        # signature does not rescue the malformed header.
        header_json = b'{"alg":"HS256","typ":"JWT","b64":false}'
        header_segment = base64url_encode(header_json)
        signing_input = b".".join([header_segment, PAYLOAD_JSON])
        token = b".".join(
            [header_segment, b"", base64url_encode(sign_hs256(signing_input))]
        ).decode()
        with pytest.raises(InvalidTokenError) as exc_info:
            jws.decode(
                token, SECRET, algorithms=ALGORITHMS, detached_payload=PAYLOAD_JSON
            )
        assert type(exc_info.value) is InvalidTokenError


class TestDetachedPayload:
    """RFC 7797 b64=false detached payloads: the supported control case and
    its finite failure mutations."""

    def test_detached_payload_roundtrip_exact_claims(self, jwt: PyJWT) -> None:
        claims = {"sub": "alice", "name": "日本語"}
        token = jwt.encode(claims, SECRET, algorithm="HS256", headers={"b64": False})
        # Compact detached form carries an empty payload segment.
        assert token.split(".")[1] == ""
        payload_json = json.dumps(claims, separators=(",", ":")).encode()
        decoded = jwt.decode(
            token, SECRET, algorithms=ALGORITHMS, detached_payload=payload_json
        )
        assert decoded == claims

    def test_detached_payload_roundtrip_binary_and_unicode_content(
        self, jws: PyJWS
    ) -> None:
        content = b"\x00\x01\xfe\xff" + "日本語 ✨".encode()
        token = jws.encode(
            content, SECRET, algorithm="HS256", is_payload_detached=True
        )
        decoded = jws.decode(
            token, SECRET, algorithms=ALGORITHMS, detached_payload=content
        )
        assert decoded == content

    def test_detached_payload_tampered_fails_signature(self, jws: PyJWS) -> None:
        token = jws.encode(
            PAYLOAD_JSON, SECRET, algorithm="HS256", is_payload_detached=True
        )
        with pytest.raises(InvalidSignatureError) as exc_info:
            jws.decode(
                token,
                SECRET,
                algorithms=ALGORITHMS,
                detached_payload=b'{"sub":"mallory"}',
            )
        assert type(exc_info.value) is InvalidSignatureError

    def test_detached_token_with_nonempty_payload_segment_rejected(
        self, jws: PyJWS
    ) -> None:
        # Compact detached form requires an empty payload segment; stuffing
        # it must be a DecodeError even with a valid signature over the
        # detached content.
        header_json = b'{"alg":"HS256","typ":"JWT","b64":false,"crit":["b64"]}'
        header_segment = base64url_encode(header_json)
        signing_input = b".".join([header_segment, PAYLOAD_JSON])
        token = b".".join(
            [
                header_segment,
                base64url_encode(b"stuffed"),
                base64url_encode(sign_hs256(signing_input)),
            ]
        ).decode()
        with pytest.raises(DecodeError) as exc_info:
            jws.decode(
                token, SECRET, algorithms=ALGORITHMS, detached_payload=PAYLOAD_JSON
            )
        assert type(exc_info.value) is DecodeError

    def test_detached_payload_argument_with_attached_token_rejected(
        self, jws: PyJWS
    ) -> None:
        token = make_token(HEADER_JSON, base64url_encode(PAYLOAD_JSON))
        with pytest.raises(DecodeError) as exc_info:
            jws.decode(
                token,
                SECRET,
                algorithms=ALGORITHMS,
                detached_payload=PAYLOAD_JSON,
            )
        assert type(exc_info.value) is DecodeError

    def test_detached_token_without_detached_payload_argument_rejected(
        self, jws: PyJWS
    ) -> None:
        token = jws.encode(
            PAYLOAD_JSON, SECRET, algorithm="HS256", is_payload_detached=True
        )
        with pytest.raises(DecodeError) as exc_info:
            jws.decode(token, SECRET, algorithms=ALGORITHMS)
        assert type(exc_info.value) is DecodeError


class TestVerifiedBytesMatchParsedClaims:
    """End-to-end: claims returned to the application are parsed from exactly
    the bytes the signature verified."""

    def test_unicode_claims_roundtrip_exact(self, jwt: PyJWT) -> None:
        claims = {
            "sub": "user-1",
            "name": "张三 日本語",
            "emoji": "✨🌟",
            "combining": "é",
        }
        token = jwt.encode(claims, SECRET, algorithm="HS256")
        # The verified bytes are the ASCII-escaped JSON spelling...
        payload_segment = token.split(".")[1]
        assert payload_segment.isascii()
        # ...and the application reads back the exact original Unicode.
        assert jwt.decode(token, SECRET, algorithms=ALGORITHMS) == claims

    def test_payload_swapped_between_valid_tokens_fails(self, jwt: PyJWT) -> None:
        # A payload that verifies under one token must not enter claim
        # parsing under another token's signature.
        token_a = make_token(HEADER_JSON, base64url_encode(b'{"sub":"alice"}'))
        token_b = make_token(HEADER_JSON, base64url_encode(b'{"sub":"bob"}'))
        head_a, _, sig_a = token_a.split(".")
        _, payload_b, _ = token_b.split(".")
        with pytest.raises(InvalidSignatureError) as exc_info:
            jwt.decode(
                ".".join([head_a, payload_b, sig_a]), SECRET, algorithms=ALGORITHMS
            )
        assert type(exc_info.value) is InvalidSignatureError

    def test_header_swapped_between_valid_tokens_fails(self, jwt: PyJWT) -> None:
        other_header = base64url_encode(b'{"alg":"HS256","typ":"JWT","kid":"2"}')
        token = make_token(HEADER_JSON, base64url_encode(PAYLOAD_JSON))
        _, payload_segment, signature_segment = token.split(".")
        swapped = ".".join([other_header.decode(), payload_segment, signature_segment])
        with pytest.raises(InvalidSignatureError) as exc_info:
            jwt.decode(swapped, SECRET, algorithms=ALGORITHMS)
        assert type(exc_info.value) is InvalidSignatureError
