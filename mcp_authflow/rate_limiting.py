"""Rate limiting utilities for OAuth endpoints."""

import secrets
import time
from collections import defaultdict
from typing import Any, Protocol


class AsyncRedisClient(Protocol):
    """Minimal async Redis interface used for rate limit storage.

    Matches the subset of ``redis.asyncio.Redis`` that this module calls.
    """

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


_REDIS_RATELIMIT_PREFIX = "mcp_auth:ratelimit:"


class SlidingWindowRateLimiter:
    """Sliding-window rate limiter for OAuth endpoints.

    Tracks requests per client within a sliding time window.

    When a Redis client is provided, state is stored in a Redis sorted set and
    is shared across all replicas and survives pod restarts.  When ``redis`` is
    ``None`` the limiter falls back to an in-process ``defaultdict`` (suitable
    for local development and single-replica deployments).

    Redis key format: ``mcp_auth:ratelimit:<client_id>:<window_seconds>``
    """

    def __init__(
        self,
        requests_per_window: int,
        window_seconds: int,
        redis: AsyncRedisClient | None = None,
    ):
        """Initialize the rate limiter.

        Args:
            requests_per_window: Maximum number of requests allowed in the window
            window_seconds: Size of the time window in seconds
            redis: Optional async Redis client for shared, persistent storage.
                   When None, falls back to in-process in-memory storage.
        """
        self.requests_per_window = requests_per_window
        self.window_seconds = window_seconds
        self._redis = redis
        self._clients: dict[str, list[float]] = defaultdict(list)

    def _redis_key(self, client_id: str) -> str:
        return f"{_REDIS_RATELIMIT_PREFIX}{client_id}:{self.window_seconds}"

    async def is_allowed(self, client_id: str) -> bool:
        """Check if the client is allowed to make a request.

        Records the request if allowed.

        Args:
            client_id: OAuth client identifier

        Returns:
            True if the request is allowed, False if rate limited
        """
        if self._redis is not None:
            return await self._is_allowed_redis(client_id)
        return self._is_allowed_memory(client_id)

    async def get_retry_after(self, client_id: str) -> int:
        """Get the number of seconds until the client can retry.

        Args:
            client_id: OAuth client identifier

        Returns:
            Number of seconds to wait before retrying (minimum 1), or 0 if
            no requests have been recorded for this client.
        """
        if self._redis is not None:
            return await self._get_retry_after_redis(client_id)
        return self._get_retry_after_memory(client_id)

    # ------------------------------------------------------------------
    # Redis-backed implementation
    # ------------------------------------------------------------------

    async def _is_allowed_redis(self, client_id: str) -> bool:
        """Redis sliding-window check using a sorted set.

        Uses ZADD + ZREMRANGEBYSCORE + ZCARD in sequence.  This is not
        atomically safe under extremely high concurrency but is sufficient at
        the scale of OAuth endpoints (a single wrong admission per burst is
        acceptable and can be over-counted by at most the number of concurrent
        callers).

        For strict atomicity a Lua script could be used; the pipeline approach
        here is simpler.
        """
        assert self._redis is not None  # guaranteed by is_allowed dispatch
        key = self._redis_key(client_id)
        now = time.time()
        window_start = now - self.window_seconds

        await self._redis.zremrangebyscore(key, "-inf", window_start)

        count = await self._redis.zcard(key)

        if count >= self.requests_per_window:
            return False

        # Use a token suffix so two requests at the same float timestamp don't
        # collide on the sorted-set member name.
        member = f"{now}:{secrets.token_hex(4)}"
        await self._redis.zadd(key, {member: now})

        await self._redis.expire(key, self.window_seconds + 1)

        return True

    async def _get_retry_after_redis(self, client_id: str) -> int:
        assert self._redis is not None  # guaranteed by get_retry_after dispatch
        key = self._redis_key(client_id)
        now = time.time()
        window_start = now - self.window_seconds
        await self._redis.zremrangebyscore(key, "-inf", window_start)
        entries: list[Any] = await self._redis.zrange(key, 0, 0, withscores=True)
        if not entries:
            return 0
        oldest_ts: float = entries[0][1]
        retry_after = int(self.window_seconds - (now - oldest_ts)) + 1
        return max(retry_after, 1)

    # ------------------------------------------------------------------
    # In-memory fallback implementation
    # ------------------------------------------------------------------

    def _is_allowed_memory(self, client_id: str) -> bool:
        now = time.time()
        self._clients[client_id] = [
            t for t in self._clients[client_id] if now - t < self.window_seconds
        ]
        if len(self._clients[client_id]) >= self.requests_per_window:
            return False
        self._clients[client_id].append(now)
        return True

    def _get_retry_after_memory(self, client_id: str) -> int:
        if not self._clients[client_id]:
            return 0
        oldest_request = min(self._clients[client_id])
        retry_after = int(self.window_seconds - (time.time() - oldest_request)) + 1
        return max(retry_after, 1)
