"""Tests for the RFC 8628 Device Authorization Grant primitives."""

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

import pytest

from mcp_authflow.device import (
    DEVICE_CODE_GRANT_TYPE,
    DeviceCodeStatus,
    DevicePollDecision,
    DevicePollDecisionKind,
    build_device_authorization_response,
    evaluate_device_poll,
    generate_device_code,
    generate_user_code,
    normalize_user_code,
)


@dataclass
class _Record:
    device_code: str
    client_id: str
    user_code: str = "ABCD-EFGH"
    scopes: str = "read"
    status: str = "pending"
    user_id: int | str | None = None
    expires_at: datetime = datetime.now(UTC) + timedelta(minutes=10)
    interval: int = 5
    last_poll_at: datetime | None = None


# ---------------------------------------------------------------------------
# generate_device_code
# ---------------------------------------------------------------------------


class TestGenerateDeviceCode:
    def test_default_length_is_64_hex_chars(self) -> None:
        code = generate_device_code()
        assert len(code) == 64
        int(code, 16)  # parses as hex

    def test_codes_are_unique(self) -> None:
        assert generate_device_code() != generate_device_code()

    def test_custom_length(self) -> None:
        assert len(generate_device_code(length=16)) == 32


# ---------------------------------------------------------------------------
# generate_user_code
# ---------------------------------------------------------------------------


class TestGenerateUserCode:
    def test_default_format(self) -> None:
        code = generate_user_code()
        assert len(code) == 9
        assert code[4] == "-"
        left, right = code.split("-")
        assert len(left) == 4
        assert len(right) == 4

    def test_alphabet_is_unambiguous_consonants(self) -> None:
        # No ambiguous chars: 0/O, 1/I/L; no vowels (avoids unintended words).
        code = generate_user_code().replace("-", "")
        forbidden = set("AEIOU0123456789")
        assert not (set(code) & forbidden)

    def test_custom_grouping(self) -> None:
        code = generate_user_code(groups=3, group_size=3, separator="_")
        assert len(code) == 11  # 3*3 + 2*1
        assert code.count("_") == 2

    def test_invalid_arguments_raise(self) -> None:
        with pytest.raises(ValueError):
            generate_user_code(groups=0)
        with pytest.raises(ValueError):
            generate_user_code(group_size=0)

    def test_below_entropy_floor_raises(self) -> None:
        # 1*1 = ~4.3 bits, 1*4 = ~17.3 bits — both below the 20-bit floor.
        with pytest.raises(ValueError, match="entropy"):
            generate_user_code(groups=1, group_size=1)
        with pytest.raises(ValueError, match="entropy"):
            generate_user_code(groups=1, group_size=4)

    def test_at_entropy_floor_succeeds(self) -> None:
        # 5 chars * log2(20) ≈ 21.6 bits — just above the floor.
        code = generate_user_code(groups=1, group_size=5)
        assert len(code) == 5


# ---------------------------------------------------------------------------
# normalize_user_code
# ---------------------------------------------------------------------------


class TestNormalizeUserCode:
    @pytest.mark.parametrize(
        "raw",
        [
            "WDJB-MJHT",
            "wdjb-mjht",
            "wdjbmjht",
            "WDJB MJHT",
            "  wdjb mjht  ",
            "w-d-j-b-m-j-h-t",
        ],
    )
    def test_canonicalizes_variants(self, raw: str) -> None:
        assert normalize_user_code(raw) == "WDJB-MJHT"

    def test_wrong_length_returns_uppercased_no_grouping(self) -> None:
        # Garbage input must not be silently re-grouped — let the lookup fail.
        assert normalize_user_code("abc") == "ABC"

    def test_custom_grouping_parameters(self) -> None:
        assert (
            normalize_user_code("abc_def_ghi", groups=3, group_size=3, separator="_")
            == "ABC_DEF_GHI"
        )


# ---------------------------------------------------------------------------
# evaluate_device_poll
# ---------------------------------------------------------------------------


NOW = datetime(2026, 1, 1, 12, 0, tzinfo=UTC)


def _rec(**overrides) -> _Record:
    base = _Record(
        device_code="dev-secret",
        client_id="client-1",
        expires_at=NOW + timedelta(minutes=10),
    )
    for k, v in overrides.items():
        setattr(base, k, v)
    return base


class TestEvaluateDevicePoll:
    def test_unknown_code_returns_invalid_grant(self) -> None:
        decision = evaluate_device_poll(
            None,
            presented_device_code="anything",
            presented_client_id="client-1",
            now=NOW,
        )
        assert decision.kind == DevicePollDecisionKind.INVALID_GRANT
        assert decision.record is None

    def test_wrong_device_code_returns_invalid_grant(self) -> None:
        decision = evaluate_device_poll(
            _rec(),
            presented_device_code="wrong",
            presented_client_id="client-1",
            now=NOW,
        )
        assert decision.kind == DevicePollDecisionKind.INVALID_GRANT

    def test_wrong_client_returns_invalid_grant(self) -> None:
        decision = evaluate_device_poll(
            _rec(),
            presented_device_code="dev-secret",
            presented_client_id="other-client",
            now=NOW,
        )
        assert decision.kind == DevicePollDecisionKind.INVALID_GRANT

    def test_expired_record(self) -> None:
        decision = evaluate_device_poll(
            _rec(expires_at=NOW - timedelta(seconds=1)),
            presented_device_code="dev-secret",
            presented_client_id="client-1",
            now=NOW,
        )
        assert decision.kind == DevicePollDecisionKind.EXPIRED_TOKEN

    def test_polling_too_fast_returns_slow_down(self) -> None:
        decision = evaluate_device_poll(
            _rec(interval=5, last_poll_at=NOW - timedelta(seconds=2)),
            presented_device_code="dev-secret",
            presented_client_id="client-1",
            now=NOW,
        )
        assert decision.kind == DevicePollDecisionKind.SLOW_DOWN
        assert decision.retry_after == 5

    def test_pending_status(self) -> None:
        decision = evaluate_device_poll(
            _rec(status="pending"),
            presented_device_code="dev-secret",
            presented_client_id="client-1",
            now=NOW,
        )
        assert decision.kind == DevicePollDecisionKind.AUTHORIZATION_PENDING

    def test_denied_status(self) -> None:
        decision = evaluate_device_poll(
            _rec(status="denied"),
            presented_device_code="dev-secret",
            presented_client_id="client-1",
            now=NOW,
        )
        assert decision.kind == DevicePollDecisionKind.ACCESS_DENIED

    def test_approved_status(self) -> None:
        rec = _rec(status="approved", user_id=42)
        decision = evaluate_device_poll(
            rec,
            presented_device_code="dev-secret",
            presented_client_id="client-1",
            now=NOW,
        )
        assert decision.kind == DevicePollDecisionKind.APPROVED
        assert decision.record is rec

    def test_unknown_status_is_invalid_grant(self) -> None:
        decision = evaluate_device_poll(
            _rec(status="bogus"),
            presented_device_code="dev-secret",
            presented_client_id="client-1",
            now=NOW,
        )
        assert decision.kind == DevicePollDecisionKind.INVALID_GRANT

    def test_naive_datetime_in_record_is_treated_as_utc(self) -> None:
        # Mirrors infra's behaviour: SQLite-backed datetimes can be naive.
        naive_expiry = (NOW + timedelta(minutes=10)).replace(tzinfo=None)
        decision = evaluate_device_poll(
            _rec(expires_at=naive_expiry, status="approved"),
            presented_device_code="dev-secret",
            presented_client_id="client-1",
            now=NOW,
        )
        assert decision.kind == DevicePollDecisionKind.APPROVED

    def test_now_defaults_to_utc_when_omitted(self) -> None:
        # Just exercise the default path; correctness is covered by explicit-now tests.
        rec = _rec(
            status="approved",
            expires_at=datetime.now(UTC) + timedelta(minutes=10),
        )
        decision = evaluate_device_poll(
            rec,
            presented_device_code="dev-secret",
            presented_client_id="client-1",
        )
        assert decision.kind == DevicePollDecisionKind.APPROVED


# ---------------------------------------------------------------------------
# build_device_authorization_response
# ---------------------------------------------------------------------------


class TestBuildDeviceAuthorizationResponse:
    def test_default_complete_uri_appends_user_code(self) -> None:
        resp = build_device_authorization_response(
            device_code="dev123",
            user_code="WDJB-MJHT",
            verification_uri="https://auth.example.com/device",
            expires_in=600,
            interval=5,
        )
        assert resp["verification_uri_complete"] == (
            "https://auth.example.com/device?code=WDJB-MJHT"
        )

    def test_explicit_complete_uri_is_passed_through(self) -> None:
        resp = build_device_authorization_response(
            device_code="dev123",
            user_code="WDJB-MJHT",
            verification_uri="https://auth.example.com/device",
            expires_in=600,
            interval=5,
            verification_uri_complete="https://short.url/abc",
        )
        assert resp["verification_uri_complete"] == "https://short.url/abc"

    def test_all_rfc8628_fields_present(self) -> None:
        resp = build_device_authorization_response(
            device_code="d",
            user_code="u",
            verification_uri="v",
            expires_in=600,
            interval=5,
        )
        assert set(resp) == {
            "device_code",
            "user_code",
            "verification_uri",
            "verification_uri_complete",
            "expires_in",
            "interval",
        }


# ---------------------------------------------------------------------------
# constants
# ---------------------------------------------------------------------------


def test_grant_type_constant() -> None:
    assert DEVICE_CODE_GRANT_TYPE == "urn:ietf:params:oauth:grant-type:device_code"


def test_status_enum_values() -> None:
    assert DeviceCodeStatus.PENDING.value == "pending"
    assert DeviceCodeStatus.APPROVED.value == "approved"
    assert DeviceCodeStatus.DENIED.value == "denied"


def test_decision_is_frozen() -> None:
    decision = DevicePollDecision(DevicePollDecisionKind.INVALID_GRANT)
    with pytest.raises(Exception):  # noqa: B017,PT011
        decision.kind = DevicePollDecisionKind.APPROVED  # type: ignore[misc]
