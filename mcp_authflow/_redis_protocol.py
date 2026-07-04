"""Shared async Redis Protocol used across the framework.

Both the sliding-window rate limiter and the JWT replay cache accept an
injected async Redis client. They previously each declared their own
``AsyncRedisClient`` Protocol describing the subset of methods they call; the
same real ``redis.asyncio.Redis`` satisfies both. This module unifies them into
a single structural type so the two nominally distinct Protocols don't drift.

Modules re-export ``AsyncRedisClient`` from here to preserve their existing
public import paths (``mcp_authflow.AsyncRedisClient`` and
``mcp_authflow.client_auth.AsyncRedisClient``).
"""

from typing import Any, Protocol


class AsyncRedisClient(Protocol):
    """Minimal async Redis interface used by this framework.

    Matches the subset of ``redis.asyncio.Redis`` invoked by the rate limiter
    (sorted-set operations) and the JWT replay cache (``set`` with ``nx``/``px``).
    """

    async def set(
        self,
        name: str,
        value: str | bytes | int,
        *,
        nx: bool = False,
        px: int | None = None,
        **kwargs: Any,  # noqa: ANN401
    ) -> bool | None: ...

    async def zadd(self, name: str, mapping: dict[str | bytes, float], **kwargs: Any) -> int: ...  # noqa: ANN401

    async def zremrangebyscore(
        self,
        name: str,
        min: float | str,
        max: float | str,  # noqa: A002
    ) -> int: ...

    async def zcard(self, name: str) -> int: ...

    async def expire(self, name: str, time: int) -> bool: ...

    async def zrange(
        self,
        name: str,
        start: int,
        end: int,
        withscores: bool = False,
    ) -> list[Any]: ...
