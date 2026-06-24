"""Device Authorization Grant (RFC 8628) authorization-server primitives.

Sans-IO building blocks for the device flow:

- :func:`generate_device_code` / :func:`generate_user_code` — secure code
  generators. ``user_code`` uses an unambiguous consonant alphabet so codes
  read cleanly aloud (per RFC 8628 §6.1).
- :func:`normalize_user_code` — accept the user's typed input ("wdjbmjht",
  "wdjb mjht", "wdjb-mjht") and produce the canonical form for lookup.
- :class:`DeviceCodeRecord` — Protocol describing the fields the AS must
  persist. Consumers implement this with their own storage (SQLAlchemy,
  Redis, in-memory) — the framework does not own the schema.
- :func:`evaluate_device_poll` — pure state machine for the token-endpoint
  ``urn:ietf:params:oauth:grant-type:device_code`` path. Returns a
  :class:`DevicePollDecision` describing what response the caller should
  emit (RFC 8628 §3.5).
- :func:`build_device_authorization_response` — assembles the RFC 8628 §3.2
  device authorization response dict.

The module deliberately does no DB I/O and no HTTP — it composes with the
Starlette response helpers in :mod:`mcp_authflow.responses`.
"""

import math
import secrets
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from typing import Protocol

DEVICE_CODE_GRANT_TYPE = "urn:ietf:params:oauth:grant-type:device_code"

# Consonants only: avoids ambiguous characters (0/O, 1/I/L) and unintended words.
# Matches the alphabet recommended by RFC 8628 §6.1 (entropy >= 20 bits for an
# 8-char code: log2(20**8) ≈ 34.6 bits).
_USER_CODE_ALPHABET = "BCDFGHJKLMNPQRSTVWXZ"

# RFC 8628 §6.1 recommends a user-code entropy floor of ~20 bits to keep the
# code space large enough to resist online brute force during the (short) device
# polling window.
_MIN_USER_CODE_ENTROPY_BITS = 20.0


class DeviceCodeStatus(StrEnum):
    """Lifecycle states for a device code as seen by the token endpoint."""

    PENDING = "pending"
    APPROVED = "approved"
    DENIED = "denied"


def generate_device_code(length: int = 32) -> str:
    """Generate a cryptographically random ``device_code``.

    Args:
        length: Number of random bytes (hex output is ``2 * length`` chars).
            Default 32 bytes (64 hex chars, ~256 bits).
    """
    return secrets.token_hex(length)


def generate_user_code(groups: int = 2, group_size: int = 4, separator: str = "-") -> str:
    """Generate a user-friendly ``user_code`` (e.g. ``"WDJB-MJHT"``).

    Args:
        groups: Number of character groups (default 2).
        group_size: Characters per group (default 4).
        separator: Separator inserted between groups.

    Returns:
        Upper-case code drawn from an unambiguous consonant alphabet.

    Raises:
        ValueError: If ``groups`` or ``group_size`` is below 1, or if the
            resulting code carries less than ~20 bits of entropy (the RFC 8628
            §6.1 floor).
    """
    if groups < 1 or group_size < 1:
        raise ValueError("groups and group_size must be >= 1")
    entropy_bits = math.log2(len(_USER_CODE_ALPHABET)) * (groups * group_size)
    if entropy_bits < _MIN_USER_CODE_ENTROPY_BITS:
        raise ValueError(
            f"user_code entropy {entropy_bits:.1f} bits is below the RFC 8628 "
            f"§6.1 minimum of {_MIN_USER_CODE_ENTROPY_BITS:.0f} bits; "
            f"increase groups or group_size"
        )
    chunks = [
        "".join(secrets.choice(_USER_CODE_ALPHABET) for _ in range(group_size))
        for _ in range(groups)
    ]
    return separator.join(chunks)


def normalize_user_code(
    user_code: str,
    groups: int = 2,
    group_size: int = 4,
    separator: str = "-",
) -> str:
    """Canonicalize a user-entered code for storage lookup.

    Strips whitespace and separators, upper-cases, then re-inserts the
    separator at the group boundary. Codes that don't have the expected
    total length are returned upper-cased without re-grouping — let the
    storage lookup fail naturally with ``invalid_grant``.
    """
    cleaned = "".join(ch for ch in user_code if ch.isalnum()).upper()
    expected = groups * group_size
    if len(cleaned) != expected:
        return cleaned
    return separator.join(cleaned[i * group_size : (i + 1) * group_size] for i in range(groups))


class DeviceCodeRecord(Protocol):
    """Storage shape the framework expects for an in-flight device authorization.

    Consumers implement this with their own ORM model (SQLAlchemy, Beanie,
    dict-in-Redis — anything). Field semantics:

    - ``device_code``: secret presented by the device at the token endpoint.
    - ``user_code``: short code displayed to the user.
    - ``client_id``: the OAuth client that initiated the authorization.
    - ``scopes``: opaque to the framework; pass through to the access token.
    - ``status``: one of the :class:`DeviceCodeStatus` string values.
    - ``user_id``: set when the user authorizes (``status == APPROVED``).
    - ``expires_at``: timezone-aware UTC datetime.
    - ``interval``: minimum seconds between polls (RFC 8628 §3.5).
    - ``last_poll_at``: timezone-aware UTC datetime, or ``None`` for first
      poll. The caller is responsible for updating this after a successful
      :func:`evaluate_device_poll` call that returns a non-``InvalidGrant``
      decision (other than ``SlowDown``).
    """

    device_code: str
    user_code: str
    client_id: str
    scopes: str
    status: str
    user_id: int | str | None
    expires_at: datetime
    interval: int
    last_poll_at: datetime | None


class DevicePollDecisionKind(StrEnum):
    """Outcome categories from :func:`evaluate_device_poll`."""

    APPROVED = "approved"
    AUTHORIZATION_PENDING = "authorization_pending"
    ACCESS_DENIED = "access_denied"
    SLOW_DOWN = "slow_down"
    EXPIRED_TOKEN = "expired_token"  # nosec B105 — RFC 8628 §3.5 error code string
    INVALID_GRANT = "invalid_grant"


@dataclass(frozen=True)
class DevicePollDecision:
    """Result of a token-endpoint device-code poll.

    ``kind`` tells the caller which response to emit; ``record`` is the
    storage row (so callers can read scopes/user_id without re-fetching);
    ``retry_after`` is the polling interval to surface in ``slow_down``
    responses.
    """

    kind: DevicePollDecisionKind
    record: DeviceCodeRecord | None = None
    retry_after: int | None = None


def _as_utc(dt: datetime) -> datetime:
    return dt.replace(tzinfo=UTC) if dt.tzinfo is None else dt


def evaluate_device_poll(
    record: DeviceCodeRecord | None,
    *,
    presented_device_code: str,
    presented_client_id: str,
    now: datetime | None = None,
) -> DevicePollDecision:
    """Decide how the token endpoint should respond to a device-code poll.

    Implements RFC 8628 §3.5:

    1. Constant-time check that the presented ``device_code`` matches the
       stored record (returns ``INVALID_GRANT`` on miss/mismatch — never
       leak whether the code exists vs. was wrong).
    2. Client binding check (``INVALID_GRANT`` if the client_id differs).
    3. Expiry check (``EXPIRED_TOKEN``).
    4. Polling-interval check against ``last_poll_at`` (``SLOW_DOWN``).
    5. Status mapping: ``pending → AUTHORIZATION_PENDING``,
       ``denied → ACCESS_DENIED``, ``approved → APPROVED``.

    The caller is responsible for updating ``record.last_poll_at = now``
    after this returns anything other than ``INVALID_GRANT``.
    """
    current = now if now is not None else datetime.now(UTC)

    if record is None or not secrets.compare_digest(
        record.device_code.encode("utf-8"), presented_device_code.encode("utf-8")
    ):
        return DevicePollDecision(DevicePollDecisionKind.INVALID_GRANT)

    if record.client_id != presented_client_id:
        return DevicePollDecision(DevicePollDecisionKind.INVALID_GRANT, record=record)

    if _as_utc(record.expires_at) < current:
        return DevicePollDecision(DevicePollDecisionKind.EXPIRED_TOKEN, record=record)

    if record.last_poll_at is not None:
        elapsed = (current - _as_utc(record.last_poll_at)).total_seconds()
        if elapsed < record.interval:
            return DevicePollDecision(
                DevicePollDecisionKind.SLOW_DOWN,
                record=record,
                retry_after=record.interval,
            )

    if record.status == DeviceCodeStatus.PENDING.value:
        return DevicePollDecision(DevicePollDecisionKind.AUTHORIZATION_PENDING, record=record)
    if record.status == DeviceCodeStatus.DENIED.value:
        return DevicePollDecision(DevicePollDecisionKind.ACCESS_DENIED, record=record)
    if record.status == DeviceCodeStatus.APPROVED.value:
        return DevicePollDecision(DevicePollDecisionKind.APPROVED, record=record)
    return DevicePollDecision(DevicePollDecisionKind.INVALID_GRANT, record=record)


def build_device_authorization_response(
    *,
    device_code: str,
    user_code: str,
    verification_uri: str,
    expires_in: int,
    interval: int,
    verification_uri_complete: str | None = None,
) -> dict[str, str | int]:
    """Assemble an RFC 8628 §3.2 device authorization response.

    If ``verification_uri_complete`` is omitted, it is derived as
    ``f"{verification_uri}?code={user_code}"`` so the user can scan a QR code
    on the device and skip typing the ``user_code``.
    """
    response: dict[str, str | int] = {
        "device_code": device_code,
        "user_code": user_code,
        "verification_uri": verification_uri,
        "verification_uri_complete": (
            verification_uri_complete
            if verification_uri_complete is not None
            else f"{verification_uri}?code={user_code}"
        ),
        "expires_in": expires_in,
        "interval": interval,
    }
    return response
