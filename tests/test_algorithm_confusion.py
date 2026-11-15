"""End-to-end tests for the JWT verification boundary.

The ``alg`` header of a JWS is attacker-controlled. When the algorithm
declared by a token does not agree with the cryptographic family of the key
the verifier trusts, the token must never be turned into usable claims.
These tests cover the full verification boundary across every entry point
exposed by the library:

* raw keys / secrets (``str`` / ``bytes`` / ``cryptography`` objects) handed
  to ``jwt.encode`` / ``jwt.decode``,
* keys imported from JWK material through :class:`jwt.api_jwk.PyJWK` and the
  per-algorithm ``from_jwk`` helpers,
* keys resolved at runtime by :class:`jwt.PyJWKClient`.

For every rejection path the tests assert both the exception type and that no
claims are returned, and for every explicitly allowed algorithm a valid login
token is still accepted with identical claims across entry points.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
from typing import Any, Union

import pytest

import jwt
from jwt.algorithms import (
    ECAlgorithm,
    HMACAlgorithm,
    NoneAlgorithm,
    OKPAlgorithm,
    RSAAlgorithm,
    has_crypto,
)
from jwt.api_jwk import PyJWK, PyJWKSet
from jwt.exceptions import (
    DecodeError,
    InvalidAlgorithmError,
    InvalidKeyError,
    InvalidSignatureError,
    InvalidTokenError,
    PyJWKError,
    PyJWKSetError,
    PyJWTError,
)

from .utils import crypto_required

if has_crypto:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa
    from cryptography.hazmat.primitives.asymmetric.ec import (
        EllipticCurvePrivateKey,
        EllipticCurvePublicKey,
    )
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey,
    )
    from cryptography.hazmat.primitives.asymmetric.rsa import (
        RSAPrivateKey,
        RSAPublicKey,
    )

    _PrivateKey = Union[RSAPrivateKey, EllipticCurvePrivateKey, Ed25519PrivateKey]


# ---------------------------------------------------------------------------
# Token-forging helpers
#
# A real algorithm-confusion attacker cannot call ``jwt.encode`` with the
# victim's public key (the library rejects that at prepare_key time). They
# craft the compact serialization directly, so the helpers below do the same.
# ---------------------------------------------------------------------------


def _b64url(data: bytes) -> bytes:
    return base64.urlsafe_b64encode(data).rstrip(b"=")


def _replace_header(token: str, header: dict[str, Any]) -> str:
    """Return *token* with a new, still unsigned JOSE header."""
    _, payload_segment, signature_segment = token.split(".")
    header_segment = _b64url(
        json.dumps(header, separators=(",", ":")).encode("utf-8")
    ).decode("utf-8")
    return f"{header_segment}.{payload_segment}.{signature_segment}"


def _hmac_token(
    payload: dict[str, Any], secret: bytes, algorithm: str = "HS256"
) -> str:
    """Forge an HS* token the way an attacker would, bypassing ``encode``."""
    hash_alg = {
        "HS256": hashlib.sha256,
        "HS384": hashlib.sha384,
        "HS512": hashlib.sha512,
    }[algorithm]
    header_segment = _b64url(
        json.dumps({"alg": algorithm, "typ": "JWT"}, separators=(",", ":")).encode()
    )
    payload_segment = _b64url(json.dumps(payload, separators=(",", ":")).encode())
    signing_input = header_segment + b"." + payload_segment
    signature = hmac.new(secret, signing_input, hash_alg).digest()
    return b".".join([header_segment, payload_segment, _b64url(signature)]).decode(
        "utf-8"
    )


def _none_token(payload: dict[str, Any], kid: str | None = None) -> str:
    """Build an unsigned ``alg=none`` token with an empty signature segment."""
    header: dict[str, Any] = {"alg": "none", "typ": "JWT"}
    if kid is not None:
        header["kid"] = kid
    header_segment = _b64url(json.dumps(header, separators=(",", ":")).encode())
    payload_segment = _b64url(json.dumps(payload, separators=(",", ":")).encode())
    return b".".join([header_segment, payload_segment, b""]).decode("utf-8")


def _private_pem(key: "_PrivateKey") -> bytes:
    return key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )


def _public_pem(key: "_PrivateKey") -> bytes:
    return key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )


# Trusted claims that a legitimate identity provider would put on a token.
TRUSTED_CLAIMS = {
    "sub": "user-42",
    "iss": "https://issuer.example/",
    "role": "member",
}

# Claims an attacker is trying to smuggle past verification.
FORGED_CLAIMS = {"sub": "attacker", "role": "admin"}

# A long enough secret to satisfy RFC 7518 key-length guidance for every HS*.
HMAC_SECRET = b"trusted-hmac-secret-with-plenty-of-entropy-0123456789"


@pytest.fixture(scope="module")
def key_material() -> dict[str, Any]:
    """Generate one matching key pair per family for the whole module."""
    rsa_private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ec_private = ec.generate_private_key(ec.SECP256R1())
    ed_private = ed25519.Ed25519PrivateKey.generate()

    return {
        "rsa_private": rsa_private,
        "rsa_public": rsa_private.public_key(),
        "rsa_public_pem": _public_pem(rsa_private),
        "rsa_private_pem": _private_pem(rsa_private),
        "ec_private": ec_private,
        "ec_public": ec_private.public_key(),
        "ec_public_pem": _public_pem(ec_private),
        "ec_private_pem": _private_pem(ec_private),
        "ed_private": ed_private,
        "ed_public": ed_private.public_key(),
        "ed_public_pem": _public_pem(ed_private),
        "ed_private_pem": _private_pem(ed_private),
    }


# ---------------------------------------------------------------------------
# 1. Cross-algorithm key reuse must never produce trusted claims
# ---------------------------------------------------------------------------


@crypto_required
class TestAlgorithmConfusionAttacks:
    """Attacker-controlled ``alg`` headers against trusted key material."""

    @pytest.mark.parametrize("hmac_alg", ["HS256", "HS384", "HS512"])
    def test_hmac_token_forged_with_rsa_public_pem_is_rejected(
        self, key_material: dict[str, Any], hmac_alg: str
    ) -> None:
        # Classic RS256 -> HS256 confusion: sign with the RSA *public* key
        # bytes as if they were an HMAC secret.
        forged = _hmac_token(
            FORGED_CLAIMS, key_material["rsa_public_pem"], algorithm=hmac_alg
        )

        with pytest.raises(InvalidKeyError) as excinfo:
            jwt.decode(
                forged,
                key_material["rsa_public_pem"],
                algorithms=[hmac_alg, "RS256"],
            )

        assert "should not be used as an HMAC secret" in str(excinfo.value)

    @pytest.mark.parametrize("hmac_alg", ["HS256", "HS384", "HS512"])
    def test_hmac_token_forged_with_ec_public_pem_is_rejected(
        self, key_material: dict[str, Any], hmac_alg: str
    ) -> None:
        forged = _hmac_token(
            FORGED_CLAIMS, key_material["ec_public_pem"], algorithm=hmac_alg
        )

        with pytest.raises(InvalidKeyError):
            jwt.decode(
                forged,
                key_material["ec_public_pem"],
                algorithms=[hmac_alg, "ES256"],
            )

    def test_hmac_token_forged_with_ed25519_public_pem_is_rejected(
        self, key_material: dict[str, Any]
    ) -> None:
        forged = _hmac_token(FORGED_CLAIMS, key_material["ed_public_pem"])

        with pytest.raises(InvalidKeyError):
            jwt.decode(
                forged,
                key_material["ed_public_pem"],
                algorithms=["HS256", "EdDSA"],
            )

    def test_hmac_token_forged_with_ssh_public_key_is_rejected(
        self, key_material: dict[str, Any]
    ) -> None:
        ssh_public = key_material["rsa_public"].public_bytes(
            encoding=serialization.Encoding.OpenSSH,
            format=serialization.PublicFormat.OpenSSH,
        )
        forged = _hmac_token(FORGED_CLAIMS, ssh_public)

        with pytest.raises(InvalidKeyError):
            jwt.decode(forged, ssh_public, algorithms=["HS256", "RS256"])

    def test_jwk_json_bytes_cannot_be_used_as_hmac_secret(
        self, key_material: dict[str, Any]
    ) -> None:
        # The verifier stores an RSA public JWK. An attacker who obtains its
        # JSON representation cannot feed those bytes in as an HMAC secret.
        jwk_dict = json.loads(RSAAlgorithm.to_jwk(key_material["rsa_public"]))
        jwk_bytes = json.dumps(jwk_dict, separators=(",", ":")).encode("utf-8")
        forged = _hmac_token(FORGED_CLAIMS, jwk_bytes)

        with pytest.raises(InvalidKeyError, match="looks like a JWK"):
            jwt.decode(forged, jwk_bytes, algorithms=["HS256"])

    def test_oct_jwk_json_bytes_cannot_be_used_as_hmac_secret(self) -> None:
        # Even a symmetric JWK must be imported through from_jwk / PyJWK;
        # its JSON serialization is not the secret material itself.
        jwk_bytes = HMACAlgorithm.to_jwk(HMAC_SECRET).encode("utf-8")
        forged = _hmac_token(FORGED_CLAIMS, jwk_bytes)

        with pytest.raises(InvalidKeyError, match="looks like a JWK"):
            jwt.decode(forged, jwk_bytes, algorithms=["HS256"])

    def test_encode_refuses_to_sign_hmac_with_asymmetric_public_key(
        self, key_material: dict[str, Any]
    ) -> None:
        # Defense in depth: the confusion attempt is stopped at encode time
        # too, not only when decoding an attacker-forged token.
        with pytest.raises(InvalidKeyError):
            jwt.encode(  # type: ignore[arg-type,unused-ignore]
                FORGED_CLAIMS, key_material["rsa_public_pem"], algorithm="HS256"
            )
        with pytest.raises(InvalidKeyError):
            jwt.encode(  # type: ignore[arg-type,unused-ignore]
                FORGED_CLAIMS, key_material["ec_public_pem"], algorithm="HS256"
            )

    def test_rsa_token_with_header_swapped_to_hmac_is_rejected(
        self, key_material: dict[str, Any]
    ) -> None:
        # Take a legitimately issued RS256 token and only rewrite its header
        # to advertise HS256, keeping the original (RSA) signature.
        legitimate = jwt.encode(
            TRUSTED_CLAIMS,
            key_material["rsa_private_pem"],
            algorithm="RS256",
        )
        tampered = _replace_header(legitimate, {"alg": "HS256", "typ": "JWT"})

        with pytest.raises(InvalidKeyError):
            jwt.decode(
                tampered,
                key_material["rsa_public_pem"],
                algorithms=["HS256", "RS256"],
            )

    def test_ec_token_with_header_swapped_to_hmac_is_rejected(
        self, key_material: dict[str, Any]
    ) -> None:
        legitimate = jwt.encode(
            TRUSTED_CLAIMS,
            key_material["ec_private_pem"],
            algorithm="ES256",
        )
        tampered = _replace_header(legitimate, {"alg": "HS256", "typ": "JWT"})

        with pytest.raises(InvalidKeyError):
            jwt.decode(
                tampered,
                key_material["ec_public_pem"],
                algorithms=["HS256", "ES256"],
            )

    def test_none_token_rejected_when_not_on_whitelist(
        self, key_material: dict[str, Any]
    ) -> None:
        forged = _none_token(FORGED_CLAIMS)

        with pytest.raises(InvalidAlgorithmError, match="not allowed"):
            jwt.decode(
                forged,
                key_material["rsa_public_pem"],
                algorithms=["RS256"],
            )

    @pytest.mark.filterwarnings(
        "ignore::BytesWarning"
    )  # NoneAlgorithm compares the key against ""; harmless under -b
    def test_none_token_rejected_even_if_whitelisted_with_key(
        self, key_material: dict[str, Any]
    ) -> None:
        # A verifier that mistakenly allows "none" still cannot be tricked
        # when a key is configured: NoneAlgorithm requires key=None.
        forged = _none_token(FORGED_CLAIMS)

        with pytest.raises(InvalidKeyError, match='alg = "none"'):
            jwt.decode(
                forged,
                key_material["rsa_public_pem"],  # type: ignore[arg-type,unused-ignore]
                algorithms=["none"],
            )

    def test_none_token_rejected_with_no_key_and_empty_signature(self) -> None:
        # Even with key=None and "none" whitelisted, the empty signature
        # fails verification: NoneAlgorithm.verify always returns False.
        forged = _none_token(FORGED_CLAIMS)

        with pytest.raises(
            InvalidSignatureError, match="Signature verification failed"
        ):
            jwt.decode(
                forged,
                key=None,  # type: ignore[arg-type,unused-ignore]
                algorithms=["none"],
            )

    def test_none_token_with_fake_signature_is_rejected(self) -> None:
        forged = _none_token(FORGED_CLAIMS)
        # Attacker appends non-empty signature material.
        forged_with_sig = forged + _b64url(b"not-a-real-signature").decode()

        with pytest.raises(InvalidSignatureError):
            jwt.decode(
                forged_with_sig,
                key=None,  # type: ignore[arg-type,unused-ignore]
                algorithms=["none"],
            )

    def test_signed_token_rejected_when_verifier_expects_none(
        self, key_material: dict[str, Any]
    ) -> None:
        # The reverse direction: a real RS256 token must not be accepted by
        # a verifier whose whitelist only contains "none".
        legitimate = jwt.encode(
            TRUSTED_CLAIMS,
            key_material["rsa_private_pem"],
            algorithm="RS256",
        )

        with pytest.raises(InvalidAlgorithmError):
            jwt.decode(
                legitimate,
                key_material["rsa_public_pem"],
                algorithms=["none"],
            )

    def test_rsa_key_cannot_verify_ec_algorithm_token(
        self, key_material: dict[str, Any]
    ) -> None:
        ec_token = jwt.encode(
            TRUSTED_CLAIMS,
            key_material["ec_private_pem"],
            algorithm="ES256",
        )

        # Whitelist permits ES256, but the configured key is an RSA key
        # object: the key family check must reject it before verification.
        with pytest.raises((InvalidKeyError, TypeError)):
            jwt.decode(
                ec_token,
                key_material["rsa_public"],
                algorithms=["ES256"],
            )

    def test_ec_key_cannot_verify_rsa_algorithm_token(
        self, key_material: dict[str, Any]
    ) -> None:
        rsa_token = jwt.encode(
            TRUSTED_CLAIMS,
            key_material["rsa_private_pem"],
            algorithm="RS256",
        )

        with pytest.raises((InvalidKeyError, TypeError)):
            jwt.decode(
                rsa_token,
                key_material["ec_public"],
                algorithms=["RS256"],
            )

    def test_ed25519_key_cannot_verify_rsa_algorithm_token(
        self, key_material: dict[str, Any]
    ) -> None:
        rsa_token = jwt.encode(
            TRUSTED_CLAIMS,
            key_material["rsa_private_pem"],
            algorithm="RS256",
        )

        with pytest.raises((InvalidKeyError, TypeError)):
            jwt.decode(
                rsa_token,
                key_material["ed_public"],
                algorithms=["RS256"],
            )


# ---------------------------------------------------------------------------
# 2. Failure semantics: error types and the absence of usable claims
# ---------------------------------------------------------------------------


@crypto_required
class TestFailureSemantics:
    def test_decode_raises_instead_of_returning_claims_on_every_failure(
        self, key_material: dict[str, Any]
    ) -> None:
        rsa_token = jwt.encode(
            TRUSTED_CLAIMS,
            key_material["rsa_private_pem"],
            algorithm="RS256",
        )
        header_segment, payload_segment, signature_segment = rsa_token.split(".")

        candidates = {
            "tampered signature": (
                f"{header_segment}.{payload_segment}.{_b64url(b'bad').decode()}"
            ),
            "tampered payload": (
                f"{header_segment}.{_b64url(json.dumps(FORGED_CLAIMS).encode()).decode()}.{signature_segment}"
            ),
            "alg=none downgrade": _none_token(FORGED_CLAIMS),
            "hmac confusion": _hmac_token(
                FORGED_CLAIMS, key_material["rsa_public_pem"]
            ),
        }

        for label, token in candidates.items():
            with pytest.raises(PyJWTError) as excinfo:
                jwt.decode(
                    token,
                    key_material["rsa_public_pem"],
                    algorithms=["RS256", "HS256"],
                )
            # Every rejection inherits from PyJWTError. Key-shape failures
            # surface as InvalidKeyError (a PyJWTError, not an
            # InvalidTokenError); token-content failures as an
            # InvalidTokenError subclass — none of them return a payload.
            assert isinstance(
                excinfo.value,
                (
                    DecodeError,
                    InvalidAlgorithmError,
                    InvalidKeyError,
                ),
            ), label

    def test_tampered_signature_raises_invalid_signature_error(
        self, key_material: dict[str, Any]
    ) -> None:
        token = jwt.encode(
            TRUSTED_CLAIMS,
            key_material["rsa_private_pem"],
            algorithm="RS256",
        )
        _, payload_segment, _ = token.split(".")
        zero_signature = _b64url(b"\x00" * 256).decode()
        tampered = f"{token.split('.')[0]}.{payload_segment}.{zero_signature}"

        with pytest.raises(
            InvalidSignatureError, match="Signature verification failed"
        ):
            jwt.decode(
                tampered,
                key_material["rsa_public_pem"],
                algorithms=["RS256"],
            )

    def test_claim_forgery_raises_invalid_signature_error(
        self, key_material: dict[str, Any]
    ) -> None:
        token = jwt.encode(
            TRUSTED_CLAIMS,
            key_material["rsa_private_pem"],
            algorithm="RS256",
        )
        header_segment, _, signature_segment = token.split(".")
        forged_payload = _b64url(
            json.dumps(FORGED_CLAIMS, separators=(",", ":")).encode()
        ).decode()

        with pytest.raises(InvalidSignatureError):
            jwt.decode(
                f"{header_segment}.{forged_payload}.{signature_segment}",
                key_material["rsa_public_pem"],
                algorithms=["RS256"],
            )

    def test_algorithm_not_on_whitelist_raises_invalid_algorithm_error(
        self, key_material: dict[str, Any]
    ) -> None:
        token = jwt.encode(
            TRUSTED_CLAIMS,
            key_material["rsa_private_pem"],
            algorithm="RS256",
        )

        with pytest.raises(InvalidAlgorithmError, match="not allowed"):
            jwt.decode(
                token,
                key_material["rsa_public_pem"],
                algorithms=["ES256"],
            )

    def test_unknown_algorithm_in_header_raises_invalid_algorithm_error(
        self, key_material: dict[str, Any]
    ) -> None:
        token = jwt.encode(
            TRUSTED_CLAIMS,
            key_material["rsa_private_pem"],
            algorithm="RS256",
        )
        tampered = _replace_header(token, {"alg": "RS9999", "typ": "JWT"})

        with pytest.raises(InvalidAlgorithmError):
            jwt.decode(
                tampered,
                key_material["rsa_public_pem"],
                algorithms=["RS9999", "RS256"],
            )

    def test_missing_algorithms_argument_raises_decode_error(
        self, key_material: dict[str, Any]
    ) -> None:
        token = jwt.encode(
            TRUSTED_CLAIMS,
            key_material["rsa_private_pem"],
            algorithm="RS256",
        )

        with pytest.raises(DecodeError, match="algorithms"):
            jwt.decode(token, key_material["rsa_public_pem"])

    def test_missing_alg_header_raises_invalid_algorithm_error(
        self, key_material: dict[str, Any]
    ) -> None:
        token = jwt.encode(
            TRUSTED_CLAIMS,
            key_material["rsa_private_pem"],
            algorithm="RS256",
        )
        _, payload_segment, signature_segment = token.split(".")
        no_alg_header = _b64url(
            json.dumps({"typ": "JWT"}, separators=(",", ":")).encode()
        ).decode()

        with pytest.raises(InvalidAlgorithmError, match="Algorithm not specified"):
            jwt.decode(
                f"{no_alg_header}.{payload_segment}.{signature_segment}",
                key_material["rsa_public_pem"],
                algorithms=["RS256"],
            )

    def test_unverified_header_does_not_grant_trust(self) -> None:
        # Reading the header never verifies anything: callers must still
        # run a full decode and handle its failure.
        forged = _none_token(FORGED_CLAIMS)
        header = jwt.get_unverified_header(forged)

        assert header["alg"] == "none"
        with pytest.raises(InvalidTokenError):
            jwt.decode(
                forged,
                key=None,  # type: ignore[arg-type,unused-ignore]
                algorithms=["none"],
            )

    def test_verify_signature_false_remains_explicitly_untrusted(self) -> None:
        forged = _none_token(FORGED_CLAIMS)

        # The only way to obtain claims from an unsigned token is an explicit
        # opt-out that documents the payload as unverified.
        unverified = jwt.decode(forged, options={"verify_signature": False})
        assert unverified == FORGED_CLAIMS
        # The same token still fails every verifying entry point.
        with pytest.raises(InvalidTokenError):
            jwt.decode(
                forged,
                key=None,  # type: ignore[arg-type,unused-ignore]
                algorithms=["none"],
            )


# ---------------------------------------------------------------------------
# 3. JWK import and PyJWK-bound algorithm semantics
# ---------------------------------------------------------------------------


@crypto_required
class TestJWKImportAndBinding:
    def test_from_jwk_rejects_cross_key_type_material(self) -> None:
        rsa_jwk = json.loads(
            RSAAlgorithm.to_jwk(
                rsa.generate_private_key(
                    public_exponent=65537, key_size=2048
                ).public_key()
            )
        )
        ec_jwk = json.loads(
            ECAlgorithm.to_jwk(ec.generate_private_key(ec.SECP256R1()).public_key())
        )

        with pytest.raises(InvalidKeyError, match="Not an HMAC key"):
            HMACAlgorithm.from_jwk(json.dumps(rsa_jwk))
        with pytest.raises(InvalidKeyError, match="Not an RSA key"):
            RSAAlgorithm.from_jwk(ec_jwk)
        with pytest.raises(InvalidKeyError, match="Not an Elliptic curve key"):
            ECAlgorithm.from_jwk(rsa_jwk)

    def test_from_jwk_rejects_invalid_json(self) -> None:
        with pytest.raises(InvalidKeyError, match="not valid JSON"):
            HMACAlgorithm.from_jwk("not-json")
        with pytest.raises(InvalidKeyError, match="not valid JSON"):
            RSAAlgorithm.from_jwk("{broken")
        with pytest.raises(InvalidKeyError, match="not valid JSON"):
            HMACAlgorithm.from_jwk(123)  # type: ignore[arg-type,unused-ignore]

    def test_pyjwk_rejects_algorithm_incompatible_with_kty(
        self, key_material: dict[str, Any]
    ) -> None:
        rsa_jwk = json.loads(RSAAlgorithm.to_jwk(key_material["rsa_public"]))
        ec_jwk = json.loads(ECAlgorithm.to_jwk(key_material["ec_public"]))

        with pytest.raises(InvalidKeyError, match="Not an RSA key"):
            PyJWK(ec_jwk, algorithm="RS256")
        with pytest.raises(InvalidKeyError, match="Not an HMAC key"):
            PyJWK(rsa_jwk, algorithm="HS256")

    def test_pyjwk_rejects_unknown_and_missing_kty(self) -> None:
        with pytest.raises(InvalidKeyError, match="Unsupported kty"):
            PyJWK({"kty": "UNKNOWN", "k": "aa"})
        with pytest.raises(InvalidKeyError, match="kty is not found"):
            PyJWK({})

    def test_pyjwk_rejects_oct_key_declared_as_asymmetric_algorithm(self) -> None:
        oct_jwk = {
            "kty": "oct",
            "alg": "ES256",
            "k": _b64url(b"x" * 32).decode(),
        }
        with pytest.raises(InvalidKeyError):
            PyJWK(oct_jwk)

    def test_pyjwk_binds_algorithm_and_rejects_header_override(
        self, key_material: dict[str, Any]
    ) -> None:
        rsa_jwk_dict = json.loads(RSAAlgorithm.to_jwk(key_material["rsa_public"]))
        rsa_jwk_dict["alg"] = "RS256"
        rsa_jwk = PyJWK(rsa_jwk_dict)

        legitimate = jwt.encode(
            TRUSTED_CLAIMS,
            key_material["rsa_private_pem"],
            algorithm="RS256",
        )
        tampered = _replace_header(legitimate, {"alg": "HS256", "typ": "JWT"})

        # Even with both algorithms on the caller's whitelist, the PyJWK is
        # bound to RS256 and refuses an HS256 header.
        with pytest.raises(
            InvalidAlgorithmError, match="does not match the key's algorithm"
        ):
            jwt.decode(tampered, rsa_jwk, algorithms=["HS256", "RS256"])

    def test_pyjwk_rejects_token_from_another_key_family(
        self, key_material: dict[str, Any]
    ) -> None:
        rsa_jwk_dict = json.loads(RSAAlgorithm.to_jwk(key_material["rsa_public"]))
        rsa_jwk_dict["alg"] = "RS256"
        rsa_jwk = PyJWK(rsa_jwk_dict)

        # A genuine ES256 token (correctly signed) cannot ride an RSA-bound
        # PyJWK, regardless of the caller's allow-list.
        ec_token = jwt.encode(
            TRUSTED_CLAIMS,
            key_material["ec_private_pem"],
            algorithm="ES256",
        )
        with pytest.raises(InvalidAlgorithmError):
            jwt.decode(ec_token, rsa_jwk, algorithms=["RS256", "ES256"])

    def test_none_algorithm_does_not_support_jwk_roundtrip(self) -> None:
        with pytest.raises(NotImplementedError):
            NoneAlgorithm.from_jwk({})
        with pytest.raises(NotImplementedError):
            NoneAlgorithm.to_jwk(None)

    def test_empty_jwk_set_and_unknown_alg_keys_are_rejected(self) -> None:
        with pytest.raises(PyJWKSetError):
            PyJWKSet.from_json(json.dumps({"keys": []}))
        with pytest.raises(PyJWKError):
            PyJWK({"kty": "oct", "alg": "HS9999", "k": _b64url(b"x" * 32).decode()})


# ---------------------------------------------------------------------------
# 4. Happy path: every explicitly allowed algorithm still works, identically
#    across every entry point, with the right key type and intact claims.
# ---------------------------------------------------------------------------


@crypto_required
class TestAllowedAlgorithmsRoundTrip:
    RSA_ALGS = ["RS256", "RS384", "RS512", "PS256", "PS384", "PS512"]

    @pytest.mark.parametrize("algorithm", RSA_ALGS)
    def test_rsa_family_round_trip_across_entry_points(
        self, key_material: dict[str, Any], algorithm: str
    ) -> None:
        token = jwt.encode(
            TRUSTED_CLAIMS,
            key_material["rsa_private_pem"],
            algorithm=algorithm,
        )

        # Entry point 1: PEM-encoded public key.
        assert (
            jwt.decode(token, key_material["rsa_public_pem"], algorithms=[algorithm])
            == TRUSTED_CLAIMS
        )
        # Entry point 2: cryptography key object, with key-type assertion.
        public_key = key_material["rsa_public"]
        assert isinstance(public_key, RSAPublicKey)
        assert jwt.decode(token, public_key, algorithms=[algorithm]) == TRUSTED_CLAIMS
        # Entry point 3: PyJWK imported from a dict.
        jwk_dict = json.loads(RSAAlgorithm.to_jwk(public_key))
        jwk_dict["alg"] = algorithm
        jwk = PyJWK(jwk_dict)
        assert jwk.key_type == "RSA"
        assert jwk.algorithm_name == algorithm
        assert jwt.decode(token, jwk) == TRUSTED_CLAIMS
        # Entry point 4: PyJWK imported from a JSON string.
        jwk_from_json = PyJWK.from_json(json.dumps(jwk_dict))
        assert jwt.decode(token, jwk_from_json) == TRUSTED_CLAIMS

    @pytest.mark.parametrize(
        ("algorithm", "curve"),
        [
            ("ES256", ec.SECP256R1()),
            ("ES384", ec.SECP384R1()),
            ("ES512", ec.SECP521R1()),
            ("ES256K", ec.SECP256K1()),
        ],
    )
    def test_ec_family_round_trip_across_entry_points(
        self, algorithm: str, curve: ec.EllipticCurve
    ) -> None:
        private_key = ec.generate_private_key(curve)
        public_key = private_key.public_key()
        assert isinstance(public_key, EllipticCurvePublicKey)
        token = jwt.encode(
            TRUSTED_CLAIMS, _private_pem(private_key), algorithm=algorithm
        )

        assert (
            jwt.decode(token, _public_pem(private_key), algorithms=[algorithm])
            == TRUSTED_CLAIMS
        )
        assert jwt.decode(token, public_key, algorithms=[algorithm]) == TRUSTED_CLAIMS

        jwk_dict = json.loads(ECAlgorithm.to_jwk(public_key))
        jwk_dict["alg"] = algorithm
        jwk = PyJWK(jwk_dict)
        assert jwk.key_type == "EC"
        assert jwk.algorithm_name == algorithm
        assert jwt.decode(token, jwk) == TRUSTED_CLAIMS
        assert (
            jwt.decode(token, PyJWK.from_json(json.dumps(jwk_dict))) == TRUSTED_CLAIMS
        )

    def test_eddsa_round_trip_across_entry_points(self) -> None:
        private_key = ed25519.Ed25519PrivateKey.generate()
        public_key = private_key.public_key()
        token = jwt.encode(TRUSTED_CLAIMS, _private_pem(private_key), algorithm="EdDSA")

        assert (
            jwt.decode(token, _public_pem(private_key), algorithms=["EdDSA"])
            == TRUSTED_CLAIMS
        )
        assert jwt.decode(token, public_key, algorithms=["EdDSA"]) == TRUSTED_CLAIMS

        jwk_dict = json.loads(OKPAlgorithm.to_jwk(public_key))
        jwk = PyJWK(jwk_dict)
        assert jwk.key_type == "OKP"
        assert jwk.algorithm_name == "EdDSA"
        assert jwt.decode(token, jwk) == TRUSTED_CLAIMS
        assert (
            jwt.decode(token, PyJWK.from_json(json.dumps(jwk_dict))) == TRUSTED_CLAIMS
        )

    @pytest.mark.parametrize("algorithm", ["HS256", "HS384", "HS512"])
    def test_hmac_round_trip_across_entry_points(self, algorithm: str) -> None:
        token = jwt.encode(TRUSTED_CLAIMS, HMAC_SECRET, algorithm=algorithm)

        # Raw secret entry point.
        assert jwt.decode(token, HMAC_SECRET, algorithms=[algorithm]) == TRUSTED_CLAIMS
        # Secret material reconstructed through the JWK import helper.
        imported_secret = HMACAlgorithm.from_jwk(HMACAlgorithm.to_jwk(HMAC_SECRET))
        assert (
            jwt.decode(token, imported_secret, algorithms=[algorithm]) == TRUSTED_CLAIMS
        )
        # PyJWK entry point (dict and JSON string).
        jwk_dict = json.loads(HMACAlgorithm.to_jwk(HMAC_SECRET))
        jwk_dict["alg"] = algorithm
        jwk = PyJWK(jwk_dict)
        assert jwk.key_type == "oct"
        assert jwk.algorithm_name == algorithm
        assert jwt.decode(token, jwk) == TRUSTED_CLAIMS
        assert (
            jwt.decode(token, PyJWK.from_json(json.dumps(jwk_dict))) == TRUSTED_CLAIMS
        )

    def test_private_key_objects_are_accepted_for_signing_and_verification(
        self, key_material: dict[str, Any]
    ) -> None:
        # Signing with an object rather than PEM must keep the same boundary:
        # only the matching family verifies the resulting token.
        assert isinstance(key_material["rsa_private"], RSAPrivateKey)
        assert isinstance(key_material["ec_private"], EllipticCurvePrivateKey)

        rsa_token = jwt.encode(
            TRUSTED_CLAIMS, key_material["rsa_private"], algorithm="RS256"
        )
        assert (
            jwt.decode(rsa_token, key_material["rsa_public"], algorithms=["RS256"])
            == TRUSTED_CLAIMS
        )

        ec_token = jwt.encode(
            TRUSTED_CLAIMS, key_material["ec_private"], algorithm="ES256"
        )
        assert (
            jwt.decode(ec_token, key_material["ec_public"], algorithms=["ES256"])
            == TRUSTED_CLAIMS
        )

    def test_none_algorithm_round_trip_is_only_possible_without_verification(
        self,
    ) -> None:
        token = jwt.encode(
            TRUSTED_CLAIMS,
            key=None,  # type: ignore[arg-type,unused-ignore]
            algorithm="none",
        )

        # The unsigned token is parseable only through the explicit
        # verification opt-out; every verifying path rejects it.
        assert jwt.decode(token, options={"verify_signature": False}) == TRUSTED_CLAIMS
        with pytest.raises(InvalidSignatureError):
            jwt.decode(
                token,
                key=None,  # type: ignore[arg-type,unused-ignore]
                algorithms=["none"],
            )
        with pytest.raises(InvalidAlgorithmError):
            jwt.decode(
                token,
                key=None,  # type: ignore[arg-type,unused-ignore]
                algorithms=["HS256"],
            )


# ---------------------------------------------------------------------------
# 5. JWKS-client entry point: keys resolved over a JWKS endpoint stay bound
# ---------------------------------------------------------------------------


class _LocalJWKClient(jwt.PyJWKClient):
    """JWKS client backed by an in-process key set (no network access)."""

    def __init__(self, key_set: dict[str, Any]) -> None:
        super().__init__("https://issuer.example/.well-known/jwks.json")
        self._key_set = key_set

    def fetch_data(self) -> dict[str, Any]:
        return self._key_set


@crypto_required
class TestJWKClientConfusionBoundary:
    @pytest.fixture()
    def rsa_jwks(self, key_material: dict[str, Any]) -> tuple[Any, dict[str, Any]]:
        jwk_dict = json.loads(RSAAlgorithm.to_jwk(key_material["rsa_public"]))
        jwk_dict.update({"alg": "RS256", "kid": "rsa-signing-key", "use": "sig"})
        return PyJWK(jwk_dict), {"keys": [jwk_dict]}

    def test_legitimate_token_verified_through_jwks_client(
        self,
        key_material: dict[str, Any],
        rsa_jwks: tuple[Any, dict[str, Any]],
    ) -> None:
        _, key_set = rsa_jwks
        client = _LocalJWKClient(key_set)
        token = jwt.encode(
            TRUSTED_CLAIMS,
            key_material["rsa_private_pem"],
            algorithm="RS256",
            headers={"kid": "rsa-signing-key"},
        )

        signing_key = client.get_signing_key_from_jwt(token)
        assert signing_key.key_type == "RSA"
        assert signing_key.algorithm_name == "RS256"
        # PyJWK binding supplies the algorithm, so no algorithms argument is
        # needed and the claims come back intact.
        assert jwt.decode(token, signing_key) == TRUSTED_CLAIMS

    def test_hmac_downgrade_through_jwks_client_is_rejected(
        self, rsa_jwks: tuple[Any, dict[str, Any]]
    ) -> None:
        _, key_set = rsa_jwks
        client = _LocalJWKClient(key_set)
        forged = jwt.encode(
            FORGED_CLAIMS,
            b"attacker-chosen-secret-0123456789abcdef",
            algorithm="HS256",
            headers={"kid": "rsa-signing-key"},
        )

        signing_key = client.get_signing_key_from_jwt(forged)
        with pytest.raises(InvalidAlgorithmError):
            jwt.decode(forged, signing_key)

    def test_none_downgrade_through_jwks_client_is_rejected(
        self, rsa_jwks: tuple[Any, dict[str, Any]]
    ) -> None:
        _, key_set = rsa_jwks
        client = _LocalJWKClient(key_set)
        forged = _none_token(FORGED_CLAIMS, kid="rsa-signing-key")

        signing_key = client.get_signing_key_from_jwt(forged)
        with pytest.raises(InvalidAlgorithmError):
            jwt.decode(forged, signing_key)

    def test_hmac_signed_with_jwk_material_through_jwks_client_is_rejected(
        self, rsa_jwks: tuple[Any, dict[str, Any]]
    ) -> None:
        _, key_set = rsa_jwks
        client = _LocalJWKClient(key_set)

        # Attacker signs HS256 using the exact JSON bytes of the public JWK.
        jwk_bytes = json.dumps(key_set["keys"][0], separators=(",", ":")).encode(
            "utf-8"
        )
        forged = _hmac_token(FORGED_CLAIMS, jwk_bytes)
        forged = _replace_header(
            forged,
            {"alg": "HS256", "typ": "JWT", "kid": "rsa-signing-key"},
        )

        signing_key = client.get_signing_key_from_jwt(forged)
        with pytest.raises(InvalidAlgorithmError):
            jwt.decode(forged, signing_key)

    def test_jwks_client_rejects_key_set_without_usable_keys(self) -> None:
        client = _LocalJWKClient({"keys": []})
        with pytest.raises(PyJWKSetError):
            client.get_jwk_set()
