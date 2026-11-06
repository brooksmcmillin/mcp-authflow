"""Rate limiting utilities for OAuth endpoints."""

import secrets
import time
from collections import defaultdict
from typing import Any, Protocol

__all__ = ["AsyncRedisClient", "SlidingWindowRateLimiter"]

_REDIS_RATELIMIT_PREFIX = "mcp_auth:ratelimit:"

_REDIS_ADMIT_SCRIPT = """
redis.call('ZREMRANGEBYSCORE', KEYS[1], '-inf', ARGV[1])
if redis.call('ZCARD', KEYS[1]) >= tonumber(ARGV[2]) then
    return 0
end
redis.call('ZADD', KEYS[1], ARGV[3], ARGV[4])
redis.call('EXPIRE', KEYS[1], ARGV[5])
return 1
"""


class AsyncRedisClient(Protocol):
    """Minimal async Redis interface used for rate-limit storage."""

    async def eval(self, script: str, numkeys: int, *keys_and_args: str | int | float) -> int: ...

    async def zremrangebyscore(
        self,
        name: str,
        min: float | str,
        max: float | str,  # noqa: A002
    ) -> int: ...

    async def zrange(
        self,
        name: str,
        start: int,
        end: int,
        withscores: bool = False,
    ) -> list[Any]: ...


class SlidingWindowRateLimiter:
    """Sliding-window rate limiter for OAuth endpoints.

    Tracks requests per client within a sliding time window.

    When a Redis client is provided, state is stored in a Redis sorted set and
    is shared across all replicas and survives pod restarts.  When ``redis`` is
    ``None`` the limiter falls back to an in-process ``defaultdict`` (suitable
    for local development and single-replica deployments).

    Redis admission uses an atomic Lua script, so the client must support
    ``EVAL`` as well as the sorted-set reads used by ``get_retry_after``.

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
        self._last_sweep = 0.0

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
        """Atomically prune, check capacity, record admission, and set expiry."""
        if self._redis is None:
            raise RuntimeError(
                "Redis client is required but was not provided; "
                "_is_allowed_redis must not be called without a Redis client."
            )
        key = self._redis_key(client_id)
        now = time.time()
        window_start = now - self.window_seconds

        # Use a token suffix so two requests at the same float timestamp don't
        # collide on the sorted-set member name.
        member = f"{now}:{secrets.token_hex(4)}"
        result = await self._redis.eval(
            _REDIS_ADMIT_SCRIPT,
            1,
            key,
            window_start,
            self.requests_per_window,
            now,
            member,
            self.window_seconds + 1,
        )
        return result == 1

    async def _get_retry_after_redis(self, client_id: str) -> int:
        if self._redis is None:
            raise RuntimeError(
                "Redis client is required but was not provided; "
                "_get_retry_after_redis must not be called without a Redis client."
            )
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
        self._sweep_expired(now)
        timestamps = [t for t in self._clients[client_id] if now - t < self.window_seconds]
        if len(timestamps) >= self.requests_per_window:
            self._clients[client_id] = timestamps
            return False
        timestamps.append(now)
        self._clients[client_id] = timestamps
        return True

    def _get_retry_after_memory(self, client_id: str) -> int:
        # Read without ``defaultdict`` autovivification so an unknown client
        # does not leave a lingering empty key behind.
        timestamps = self._clients.get(client_id)
        if not timestamps:
            return 0
        oldest_request = min(timestamps)
        retry_after = int(self.window_seconds - (time.time() - oldest_request)) + 1
        return max(retry_after, 1)

    def _sweep_expired(self, now: float) -> None:
        """Drop client keys whose requests have all aged out of the window.

        Without this the in-memory ``_clients`` dict grows unboundedly: a
        client that stops calling (e.g. a caller rotating source IPs, since the
        registration handler keys the limiter on client IP) leaves a stale entry
        that per-request filtering never revisits (CWE-770). The sweep is
        throttled to at most once per window so it stays O(1) amortised.
        """
        if now - self._last_sweep < self.window_seconds:
            return
        self._last_sweep = now
        cutoff = now - self.window_seconds
        stale = [
            client_id
            for client_id, timestamps in self._clients.items()
            if not timestamps or max(timestamps) < cutoff
        ]
        for client_id in stale:
            del self._clients[client_id]
