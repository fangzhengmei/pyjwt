"""Identity-boundary tests for claim validation code shared between SSO services.

Several relying parties can share the same PyJWT validation code and signing key,
but each service keeps its own identity boundary through the ``aud`` claim. These
tests pin a single, frozen clock and combine the time claims (``exp``/``nbf``/
``iat``) with audience policies so that:

* required claims, leeway and the per-claim ``verify_*`` opt-outs behave exactly
  as documented, including at their inclusive/exclusive boundaries;
* a token minted for another service cannot be replayed at this service, and
  relaxing a *time* option never accidentally disables the audience constraint;
* normal tokens and legal multi-audience tokens stay accepted, while every
  rejection is asserted with its precise exception type and reason string.
"""

from collections.abc import Iterable, Iterator, Mapping
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, cast
from unittest import mock

import pytest

from jwt.api_jwt import PyJWT
from jwt.exceptions import (
    ExpiredSignatureError,
    ImmatureSignatureError,
    InvalidAudienceError,
    MissingRequiredClaimError,
)
from jwt.types import Options

# Fixed wall-clock time for every test: real ``datetime.now()`` is never read,
# so the time-claim boundaries below are deterministic instead of racy.
FROZEN_NOW = 1_700_000_000

# An HMAC secret shared by the SSO services (>= 32 bytes for HS256, so no
# InsecureKeyLengthWarning is emitted under the test suite's "warnings are
# errors" filter).
SHARED_SECRET = "sso-shared-hmac-secret-0123456789abcdef"

# Relying parties. Service A is the service under test; B is a sibling service;
# C is a service that must never accept either token.
SERVICE_A = "https://service-a.example.com"
SERVICE_B = "https://service-b.example.com"
SERVICE_C = "https://service-c.example.com"

# Sentinel for table-driven cases: the claim must be removed from the payload.
DROP = object()


@pytest.fixture
def jwt() -> PyJWT:
    return PyJWT()


@pytest.fixture
def frozen_clock() -> Iterator[float]:
    """Freeze ``jwt.api_jwt.datetime.now()`` at ``FROZEN_NOW``.

    The patch is a real ``datetime`` subclass so ``isinstance`` checks done by
    ``encode`` keep working; only ``now()`` is pinned.
    """
    frozen = datetime.fromtimestamp(FROZEN_NOW, tz=timezone.utc)

    class FrozenDateTime(datetime):
        @classmethod
        def now(cls, tz: Any = None) -> datetime:  # type: ignore[override]
            return frozen if tz is None else frozen.astimezone(tz)

    with mock.patch("jwt.api_jwt.datetime", FrozenDateTime):
        yield float(FROZEN_NOW)


def base_claims() -> dict[str, object]:
    """A complete, currently-valid claimset shared by the SSO infrastructure.

    It carries every time claim plus a multi-audience list, exercising the
    combination of exp/nbf/iat and audience policy in a single token.
    """
    return {
        "iss": "https://sso.example.com",
        "sub": "user-4242",
        "iat": FROZEN_NOW - 60,
        "nbf": FROZEN_NOW - 30,
        "exp": FROZEN_NOW + 300,
        "aud": [SERVICE_A, SERVICE_B],
    }


def make_token(jwt: PyJWT, claims: dict[str, object]) -> str:
    return jwt.encode(claims, SHARED_SECRET, algorithm="HS256")


def decode_token(
    jwt: PyJWT,
    token: str,
    *,
    audience: str | Iterable[str] | None = SERVICE_A,
    options: Options | None = None,
    leeway: float | timedelta = 0,
) -> dict[str, Any]:
    return jwt.decode(
        token,
        SHARED_SECRET,
        algorithms=["HS256"],
        audience=audience,
        options=options,
        leeway=leeway,
    )


def apply_changes(
    claims: dict[str, object], changes: Mapping[str, object]
) -> dict[str, object]:
    for claim, value in changes.items():
        if value is DROP:
            claims.pop(claim, None)
        else:
            claims[claim] = value
    return claims


class TestSSOClaimIdentityBoundaries:
    # ------------------------------------------------------------------
    # 1. Fixed clock: time claims, required claims, leeway and opt-outs
    # ------------------------------------------------------------------

    def test_complete_claimset_with_time_claims_and_audience_list_accepted(
        self, jwt: PyJWT, frozen_clock: float
    ) -> None:
        claims = base_claims()
        token = make_token(jwt, claims)

        # Both listed services accept the same multi-audience token.
        assert decode_token(jwt, token, audience=SERVICE_A) == claims
        assert decode_token(jwt, token, audience=SERVICE_B) == claims

    @pytest.mark.parametrize("claim", ["exp", "nbf", "iat", "aud"])
    def test_missing_required_claim_is_rejected_with_claim_name(
        self, jwt: PyJWT, frozen_clock: float, claim: str
    ) -> None:
        claims = apply_changes(base_claims(), {claim: DROP})
        token = make_token(jwt, claims)

        with pytest.raises(MissingRequiredClaimError) as exc:
            decode_token(jwt, token, options={"require": [claim]})

        assert exc.value.claim == claim
        assert str(exc.value) == f'Token is missing the "{claim}" claim'

    def test_required_claims_are_checked_before_time_and_audience_rules(
        self, jwt: PyJWT, frozen_clock: float
    ) -> None:
        # Expired and audience-less at once: the required-claim gate runs
        # first, so the reported reason must be the missing claim, not expiry.
        claims = apply_changes(base_claims(), {"exp": FROZEN_NOW - 1, "aud": DROP})
        token = make_token(jwt, claims)

        with pytest.raises(MissingRequiredClaimError) as exc:
            decode_token(jwt, token, options={"require": ["aud"]})

        assert exc.value.claim == "aud"

    def test_exp_boundary_is_inclusive_at_now(
        self, jwt: PyJWT, frozen_clock: float
    ) -> None:
        expired = make_token(jwt, apply_changes(base_claims(), {"exp": FROZEN_NOW}))
        with pytest.raises(ExpiredSignatureError) as exc:
            decode_token(jwt, expired)
        assert str(exc.value) == "Signature has expired"

        valid = make_token(jwt, apply_changes(base_claims(), {"exp": FROZEN_NOW + 1}))
        assert decode_token(jwt, valid)["exp"] == FROZEN_NOW + 1

    @pytest.mark.parametrize(
        "leeway",
        [11, timedelta(seconds=11)],
        ids=["seconds-inside", "timedelta-inside"],
    )
    def test_exp_leeway_accepts_token_inside_margin(
        self, jwt: PyJWT, frozen_clock: float, leeway: float | timedelta
    ) -> None:
        claims = apply_changes(base_claims(), {"exp": FROZEN_NOW - 10})
        token = make_token(jwt, claims)

        assert decode_token(jwt, token, leeway=leeway) == claims

    @pytest.mark.parametrize(
        "leeway",
        [10, timedelta(seconds=10)],
        ids=["seconds-at-boundary", "timedelta-at-boundary"],
    )
    def test_exp_leeway_still_rejects_token_at_exact_boundary(
        self, jwt: PyJWT, frozen_clock: float, leeway: float | timedelta
    ) -> None:
        # exp == now - leeway: the expiration comparison is ``exp <= now -
        # leeway``, so equality still counts as expired.
        token = make_token(jwt, apply_changes(base_claims(), {"exp": FROZEN_NOW - 10}))

        with pytest.raises(ExpiredSignatureError, match="Signature has expired"):
            decode_token(jwt, token, leeway=leeway)

    def test_nbf_boundary_and_leeway(self, jwt: PyJWT, frozen_clock: float) -> None:
        # nbf == now is valid: the check is the strict comparison ``nbf > now``.
        ready_now = make_token(jwt, apply_changes(base_claims(), {"nbf": FROZEN_NOW}))
        assert decode_token(jwt, ready_now)["nbf"] == FROZEN_NOW

        # One second in the future without leeway is immature.
        not_ready = make_token(
            jwt, apply_changes(base_claims(), {"nbf": FROZEN_NOW + 1})
        )
        with pytest.raises(ImmatureSignatureError) as exc:
            decode_token(jwt, not_ready)
        assert str(exc.value) == "The token is not yet valid (nbf)"

        # At nbf == now + 10, leeway of 10 reaches the boundary exactly and
        # ``nbf > now + leeway`` is false, while leeway of 9 still rejects.
        future_nbf = make_token(
            jwt, apply_changes(base_claims(), {"nbf": FROZEN_NOW + 10})
        )
        assert decode_token(jwt, future_nbf, leeway=10)["nbf"] == FROZEN_NOW + 10
        with pytest.raises(ImmatureSignatureError, match=r"\(nbf\)"):
            decode_token(jwt, future_nbf, leeway=9)

    def test_iat_boundary_and_leeway(self, jwt: PyJWT, frozen_clock: float) -> None:
        # iat in the future is reported as an immature *iat* (distinct from nbf).
        future_iat = make_token(
            jwt, apply_changes(base_claims(), {"iat": FROZEN_NOW + 1})
        )
        with pytest.raises(ImmatureSignatureError) as exc:
            decode_token(jwt, future_iat)
        assert str(exc.value) == "The token is not yet valid (iat)"

        # Same semantics as nbf: equality against now + leeway is accepted.
        far_future_iat = make_token(
            jwt, apply_changes(base_claims(), {"iat": FROZEN_NOW + 10})
        )
        assert decode_token(jwt, far_future_iat, leeway=10)["iat"] == FROZEN_NOW + 10
        with pytest.raises(ImmatureSignatureError, match=r"\(iat\)"):
            decode_token(jwt, far_future_iat, leeway=9)

        issued_now = make_token(jwt, apply_changes(base_claims(), {"iat": FROZEN_NOW}))
        assert decode_token(jwt, issued_now)["iat"] == FROZEN_NOW

    def test_verify_exp_false_does_not_disable_nbf(
        self, jwt: PyJWT, frozen_clock: float
    ) -> None:
        # Both constraints are violated on purpose.
        claims = apply_changes(
            base_claims(),
            {"exp": FROZEN_NOW - 10, "nbf": FROZEN_NOW + 10},
        )
        token = make_token(jwt, claims)

        # Turning exp off leaves the not-before gate active.
        with pytest.raises(ImmatureSignatureError, match=r"\(nbf\)"):
            decode_token(jwt, token, options={"verify_exp": False})

        # Only switching nbf off as well makes the token decode.
        assert (
            decode_token(jwt, token, options={"verify_exp": False, "verify_nbf": False})
            == claims
        )

    def test_verify_nbf_false_does_not_disable_exp(
        self, jwt: PyJWT, frozen_clock: float
    ) -> None:
        claims = apply_changes(
            base_claims(),
            {"exp": FROZEN_NOW - 10, "nbf": FROZEN_NOW + 10},
        )
        token = make_token(jwt, claims)

        with pytest.raises(ExpiredSignatureError, match="Signature has expired"):
            decode_token(jwt, token, options={"verify_nbf": False})

    def test_verify_iat_false_does_not_disable_nbf_or_exp(
        self, jwt: PyJWT, frozen_clock: float
    ) -> None:
        # Future iat combined with a future nbf: nbf must still fire.
        token_with_future_nbf = make_token(
            jwt,
            apply_changes(
                base_claims(),
                {"iat": FROZEN_NOW + 100, "nbf": FROZEN_NOW + 100},
            ),
        )
        with pytest.raises(ImmatureSignatureError, match=r"\(nbf\)"):
            decode_token(jwt, token_with_future_nbf, options={"verify_iat": False})

        # Future iat combined with an expired exp: exp must still fire.
        expired_token = make_token(
            jwt,
            apply_changes(
                base_claims(),
                {"iat": FROZEN_NOW + 100, "exp": FROZEN_NOW - 1},
            ),
        )
        with pytest.raises(ExpiredSignatureError):
            decode_token(jwt, expired_token, options={"verify_iat": False})

    def test_verify_aud_false_is_scoped_to_audience_only(
        self, jwt: PyJWT, frozen_clock: float
    ) -> None:
        # Token minted for service B: normally rejected at A, but the explicit
        # verify_aud=False escape hatch accepts it.
        foreign_token = make_token(
            jwt, apply_changes(base_claims(), {"aud": SERVICE_B})
        )
        decoded = decode_token(jwt, foreign_token, options={"verify_aud": False})
        assert decoded["aud"] == SERVICE_B

        # The same opt-out must not silence time validation: an expired
        # foreign-audience token still fails on exp.
        expired_foreign = make_token(
            jwt,
            apply_changes(
                base_claims(),
                {"aud": SERVICE_B, "exp": FROZEN_NOW - 1},
            ),
        )
        with pytest.raises(ExpiredSignatureError):
            decode_token(jwt, expired_foreign, options={"verify_aud": False})

    # ------------------------------------------------------------------
    # 2. Cross-service misuse: audience keeps the identity boundary
    # ------------------------------------------------------------------

    def test_token_minted_for_other_service_is_rejected(
        self, jwt: PyJWT, frozen_clock: float
    ) -> None:
        token = make_token(jwt, apply_changes(base_claims(), {"aud": SERVICE_B}))

        with pytest.raises(InvalidAudienceError) as exc:
            decode_token(jwt, token, audience=SERVICE_A)
        assert str(exc.value) == "Audience doesn't match"

    @pytest.mark.parametrize(
        "option",
        ["verify_exp", "verify_nbf", "verify_iat"],
    )
    def test_relaxing_one_time_option_still_rejects_foreign_audience(
        self, jwt: PyJWT, frozen_clock: float, option: str
    ) -> None:
        token = make_token(jwt, apply_changes(base_claims(), {"aud": SERVICE_B}))
        options = cast(Options, {option: False})

        with pytest.raises(InvalidAudienceError, match="Audience doesn't match"):
            decode_token(jwt, token, options=options)

    def test_relaxing_all_time_options_still_rejects_foreign_audience(
        self, jwt: PyJWT, frozen_clock: float
    ) -> None:
        token = make_token(jwt, apply_changes(base_claims(), {"aud": SERVICE_B}))

        with pytest.raises(InvalidAudienceError, match="Audience doesn't match"):
            decode_token(
                jwt,
                token,
                options={
                    "verify_exp": False,
                    "verify_nbf": False,
                    "verify_iat": False,
                },
            )

    def test_foreign_audience_with_future_nbf_reports_the_time_failure_first(
        self, jwt: PyJWT, frozen_clock: float
    ) -> None:
        # Time claims are validated before aud: the precise reason here is the
        # immature nbf, not the audience mismatch (which would fire afterwards).
        token = make_token(
            jwt,
            apply_changes(
                base_claims(),
                {"aud": SERVICE_B, "nbf": FROZEN_NOW + 10},
            ),
        )

        with pytest.raises(ImmatureSignatureError) as exc:
            decode_token(jwt, token, audience=SERVICE_A)
        assert str(exc.value) == "The token is not yet valid (nbf)"

    def test_verifier_without_expected_audience_rejects_token_with_aud(
        self, jwt: PyJWT, frozen_clock: float
    ) -> None:
        token = make_token(jwt, base_claims())

        with pytest.raises(InvalidAudienceError) as exc:
            decode_token(jwt, token, audience=None)
        assert str(exc.value) == "Invalid audience"

    def test_token_without_aud_claim_is_rejected_when_audience_expected(
        self, jwt: PyJWT, frozen_clock: float
    ) -> None:
        token = make_token(jwt, apply_changes(base_claims(), {"aud": DROP}))

        with pytest.raises(MissingRequiredClaimError) as exc:
            decode_token(jwt, token, audience=SERVICE_A)
        assert exc.value.claim == "aud"

    def test_strict_aud_accepts_only_exact_string_identity(
        self, jwt: PyJWT, frozen_clock: float
    ) -> None:
        token = make_token(jwt, apply_changes(base_claims(), {"aud": SERVICE_A}))

        # Exact string match is accepted.
        assert (
            decode_token(
                jwt,
                token,
                audience=SERVICE_A,
                options={"strict_aud": True},
            )["aud"]
            == SERVICE_A
        )

        # Different string identity is rejected with the strict reason.
        with pytest.raises(
            InvalidAudienceError, match=r"Audience doesn't match \(strict\)"
        ):
            decode_token(
                jwt,
                token,
                audience=SERVICE_B,
                options={"strict_aud": True},
            )

    def test_strict_aud_forbids_list_audience_parameter(
        self, jwt: PyJWT, frozen_clock: float
    ) -> None:
        token = make_token(jwt, apply_changes(base_claims(), {"aud": SERVICE_A}))

        with pytest.raises(InvalidAudienceError, match=r"Invalid audience \(strict\)"):
            decode_token(
                jwt,
                token,
                audience=[SERVICE_A, SERVICE_B],
                options={"strict_aud": True},
            )

    def test_strict_aud_forbids_list_audience_claim(
        self, jwt: PyJWT, frozen_clock: float
    ) -> None:
        # base_claims() carries an aud list: legal under normal matching but
        # forbidden when a service pins itself to strict single-audience mode.
        token = make_token(jwt, base_claims())

        with pytest.raises(
            InvalidAudienceError,
            match=r"Invalid claim format in token \(strict\)",
        ):
            decode_token(
                jwt,
                token,
                audience=SERVICE_A,
                options={"strict_aud": True},
            )

    # ------------------------------------------------------------------
    # 3. Accepted tokens and exact per-reason rejection matrix
    # ------------------------------------------------------------------

    def test_normal_single_audience_token_is_accepted(
        self, jwt: PyJWT, frozen_clock: float
    ) -> None:
        claims = apply_changes(base_claims(), {"aud": SERVICE_A})
        token = make_token(jwt, claims)

        assert decode_token(jwt, token) == claims

    def test_legal_multi_audience_token_accepted_by_each_listed_service(
        self, jwt: PyJWT, frozen_clock: float
    ) -> None:
        claims = base_claims()
        token = make_token(jwt, claims)

        # String audience matching either listed service.
        assert decode_token(jwt, token, audience=SERVICE_A) == claims
        assert decode_token(jwt, token, audience=SERVICE_B) == claims

        # Iterable audience with one overlapping member.
        assert decode_token(jwt, token, audience=[SERVICE_B, SERVICE_C]) == claims

    def test_multi_audience_token_rejected_for_unlisted_service(
        self, jwt: PyJWT, frozen_clock: float
    ) -> None:
        token = make_token(jwt, base_claims())

        with pytest.raises(InvalidAudienceError) as exc:
            decode_token(jwt, token, audience=SERVICE_C)
        assert str(exc.value) == "Audience doesn't match"

    @dataclass(frozen=True)
    class RejectionCase:
        name: str
        changes: Mapping[str, object]
        audience: str | Iterable[str] | None
        options: Options | None
        expected: type[Exception]
        reason: str

    REJECTION_CASES = [
        RejectionCase(
            name="expired",
            changes={"exp": FROZEN_NOW - 1},
            audience=SERVICE_A,
            options=None,
            expected=ExpiredSignatureError,
            reason="Signature has expired",
        ),
        RejectionCase(
            name="future-nbf",
            changes={"nbf": FROZEN_NOW + 10},
            audience=SERVICE_A,
            options=None,
            expected=ImmatureSignatureError,
            reason="The token is not yet valid (nbf)",
        ),
        RejectionCase(
            name="future-iat",
            changes={"iat": FROZEN_NOW + 10},
            audience=SERVICE_A,
            options=None,
            expected=ImmatureSignatureError,
            reason="The token is not yet valid (iat)",
        ),
        RejectionCase(
            name="foreign-audience",
            changes={"aud": SERVICE_B},
            audience=SERVICE_A,
            options=None,
            expected=InvalidAudienceError,
            reason="Audience doesn't match",
        ),
        RejectionCase(
            name="audience-not-expected-by-verifier",
            changes={},
            audience=None,
            options=None,
            expected=InvalidAudienceError,
            reason="Invalid audience",
        ),
        RejectionCase(
            name="missing-aud-claim",
            changes={"aud": DROP},
            audience=SERVICE_A,
            options=None,
            expected=MissingRequiredClaimError,
            reason='Token is missing the "aud" claim',
        ),
        RejectionCase(
            name="required-exp-claim-missing",
            changes={"exp": DROP},
            audience=SERVICE_A,
            options={"require": ["exp"]},
            expected=MissingRequiredClaimError,
            reason='Token is missing the "exp" claim',
        ),
        RejectionCase(
            name="non-list-aud-claim-format",
            changes={"aud": 123},
            audience=SERVICE_A,
            options=None,
            expected=InvalidAudienceError,
            reason="Invalid claim format in token",
        ),
        RejectionCase(
            name="non-string-aud-list-member",
            changes={"aud": [SERVICE_A, 1]},
            audience=SERVICE_A,
            options=None,
            expected=InvalidAudienceError,
            reason="Invalid claim format in token",
        ),
        RejectionCase(
            name="time-relaxed-but-audience-still-enforced",
            changes={"aud": SERVICE_B},
            audience=SERVICE_A,
            options={
                "verify_exp": False,
                "verify_nbf": False,
                "verify_iat": False,
            },
            expected=InvalidAudienceError,
            reason="Audience doesn't match",
        ),
    ]

    @pytest.mark.parametrize(
        "case",
        REJECTION_CASES,
        ids=[case.name for case in REJECTION_CASES],
    )
    def test_each_rejection_reason_is_asserted_exactly(
        self,
        jwt: PyJWT,
        frozen_clock: float,
        case: "TestSSOClaimIdentityBoundaries.RejectionCase",
    ) -> None:
        token = make_token(jwt, apply_changes(base_claims(), case.changes))

        with pytest.raises(case.expected) as exc:
            decode_token(
                jwt,
                token,
                audience=case.audience,
                options=case.options,
            )

        # Exact exception type, not merely a matching base class.
        assert type(exc.value) is case.expected
        assert str(exc.value) == case.reason
        if isinstance(exc.value, MissingRequiredClaimError):
            assert exc.value.claim in case.reason
