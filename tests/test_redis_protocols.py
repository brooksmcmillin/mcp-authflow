"""Static and runtime coverage for the two narrow Redis integration protocols."""

from typing import Any

from mcp_authflow.client_auth import JWTClientAuthenticator
from mcp_authflow.rate_limiting import SlidingWindowRateLimiter


class _RateLimitRedis:
    async def zadd(self, name: str, mapping: dict[str | bytes, float], **kwargs: Any) -> int:
        return 1

    async def zremrangebyscore(self, name: str, min: float | str, max: float | str) -> int:
        return 0

    async def zcard(self, name: str) -> int:
        return 0

    async def expire(self, name: str, time: int) -> bool:
        return True

    async def zrange(self, name: str, start: int, end: int, withscores: bool = False) -> list[Any]:
        return []


class _ReplayRedis:
    async def set(
        self,
        name: str,
        value: str | bytes | int,
        *,
        nx: bool = False,
        px: int | None = None,
        **kwargs: Any,
    ) -> bool | None:
        return True


class _JWKSProvider:
    async def get_jwks(self, client_id: str) -> dict[str, Any] | None:
        return None


def test_rate_limiter_accepts_sorted_set_only_adapter() -> None:
    limiter = SlidingWindowRateLimiter(10, 60, redis=_RateLimitRedis())
    assert limiter._redis is not None


def test_jwt_authenticator_accepts_set_only_adapter() -> None:
    authenticator = JWTClientAuthenticator(
        "https://auth.example.com/token",
        _JWKSProvider(),
        redis=_ReplayRedis(),
    )
    assert authenticator._redis is not None
