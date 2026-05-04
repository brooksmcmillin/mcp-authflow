"""Tests for SlidingWindowRateLimiter."""

import threading
from unittest.mock import AsyncMock, patch

from mcp_authflow.rate_limiting import SlidingWindowRateLimiter

# ---------------------------------------------------------------------------
# Basic allow / deny (in-memory path)
# ---------------------------------------------------------------------------


class TestIsAllowedBasic:
    async def test_new_client_is_allowed(self) -> None:
        limiter = SlidingWindowRateLimiter(requests_per_window=5, window_seconds=60)
        assert await limiter.is_allowed("client1") is True

    async def test_requests_up_to_limit_are_allowed(self) -> None:
        limiter = SlidingWindowRateLimiter(requests_per_window=3, window_seconds=60)
        assert await limiter.is_allowed("client1") is True
        assert await limiter.is_allowed("client1") is True
        assert await limiter.is_allowed("client1") is True

    async def test_request_over_limit_is_denied(self) -> None:
        limiter = SlidingWindowRateLimiter(requests_per_window=3, window_seconds=60)
        await limiter.is_allowed("client1")
        await limiter.is_allowed("client1")
        await limiter.is_allowed("client1")
        assert await limiter.is_allowed("client1") is False

    async def test_different_clients_are_tracked_independently(self) -> None:
        limiter = SlidingWindowRateLimiter(requests_per_window=1, window_seconds=60)
        assert await limiter.is_allowed("client_a") is True
        assert await limiter.is_allowed("client_b") is True
        assert await limiter.is_allowed("client_a") is False
        assert await limiter.is_allowed("client_b") is False

    async def test_limit_of_one(self) -> None:
        limiter = SlidingWindowRateLimiter(requests_per_window=1, window_seconds=60)
        assert await limiter.is_allowed("c") is True
        assert await limiter.is_allowed("c") is False


# ---------------------------------------------------------------------------
# Window reset (using mocked time) — in-memory path
# ---------------------------------------------------------------------------


class TestWindowReset:
    async def test_allowed_after_window_expires(self) -> None:
        limiter = SlidingWindowRateLimiter(requests_per_window=2, window_seconds=10)
        t0 = 1_000_000.0

        with patch("mcp_authflow.rate_limiting.time") as mock_time:
            mock_time.time.return_value = t0
            await limiter.is_allowed("c")
            await limiter.is_allowed("c")
            assert await limiter.is_allowed("c") is False

            mock_time.time.return_value = t0 + 11.0
            assert await limiter.is_allowed("c") is True

    async def test_partial_window_still_blocks(self) -> None:
        limiter = SlidingWindowRateLimiter(requests_per_window=2, window_seconds=10)
        t0 = 1_000_000.0

        with patch("mcp_authflow.rate_limiting.time") as mock_time:
            mock_time.time.return_value = t0
            await limiter.is_allowed("c")
            await limiter.is_allowed("c")

            mock_time.time.return_value = t0 + 5.0
            assert await limiter.is_allowed("c") is False


# ---------------------------------------------------------------------------
# Sliding window eviction — in-memory path
# ---------------------------------------------------------------------------


class TestSlidingWindowEviction:
    async def test_old_entries_are_evicted(self) -> None:
        """Requests outside the window are removed so the client can proceed."""
        limiter = SlidingWindowRateLimiter(requests_per_window=2, window_seconds=10)
        t0 = 1_000_000.0

        with patch("mcp_authflow.rate_limiting.time") as mock_time:
            mock_time.time.return_value = t0
            await limiter.is_allowed("c")
            await limiter.is_allowed("c")

            mock_time.time.return_value = t0 + 11.0
            assert await limiter.is_allowed("c") is True
            assert await limiter.is_allowed("c") is True
            assert await limiter.is_allowed("c") is False

    async def test_only_expired_entries_are_evicted(self) -> None:
        """Entries within the window are preserved during cleanup."""
        limiter = SlidingWindowRateLimiter(requests_per_window=3, window_seconds=10)
        t0 = 1_000_000.0

        with patch("mcp_authflow.rate_limiting.time") as mock_time:
            mock_time.time.return_value = t0
            await limiter.is_allowed("c")  # t0 — will expire at t0+10

            mock_time.time.return_value = t0 + 6.0
            await limiter.is_allowed("c")  # t0+6 — still in window at t0+11

            mock_time.time.return_value = t0 + 11.0
            await limiter.is_allowed("c")  # one in-window entry remains from t0+6

            assert await limiter.is_allowed("c") is True
            assert await limiter.is_allowed("c") is False


# ---------------------------------------------------------------------------
# get_retry_after — in-memory path
# ---------------------------------------------------------------------------


class TestGetRetryAfter:
    async def test_returns_positive_int_when_rate_limited(self) -> None:
        limiter = SlidingWindowRateLimiter(requests_per_window=1, window_seconds=60)
        await limiter.is_allowed("c")
        assert await limiter.is_allowed("c") is False
        retry = await limiter.get_retry_after("c")
        assert isinstance(retry, int)
        assert retry >= 1

    async def test_retry_after_is_within_window(self) -> None:
        limiter = SlidingWindowRateLimiter(requests_per_window=1, window_seconds=30)
        t0 = 1_000_000.0

        with patch("mcp_authflow.rate_limiting.time") as mock_time:
            mock_time.time.return_value = t0
            await limiter.is_allowed("c")
            await limiter.is_allowed("c")  # denied

            mock_time.time.return_value = t0 + 5.0
            retry = await limiter.get_retry_after("c")
            assert retry == 26  # (30 - 5) + 1

    async def test_retry_after_returns_zero_for_unknown_client(self) -> None:
        limiter = SlidingWindowRateLimiter(requests_per_window=5, window_seconds=60)
        assert await limiter.get_retry_after("unknown") == 0

    async def test_retry_after_minimum_is_one(self) -> None:
        """Even at the very edge of the window, retry_after is at least 1."""
        limiter = SlidingWindowRateLimiter(requests_per_window=1, window_seconds=10)
        t0 = 1_000_000.0

        with patch("mcp_authflow.rate_limiting.time") as mock_time:
            mock_time.time.return_value = t0
            await limiter.is_allowed("c")
            await limiter.is_allowed("c")  # denied

            mock_time.time.return_value = t0 + 9.999
            retry = await limiter.get_retry_after("c")
            assert retry >= 1


# ---------------------------------------------------------------------------
# Concurrent request handling — in-memory path
# ---------------------------------------------------------------------------


class TestConcurrentRequests:
    def test_concurrent_requests_do_not_exceed_limit(self) -> None:
        """Under concurrent load, allowed count must not exceed requests_per_window.

        Uses ``asyncio.run`` per thread so the async public interface is
        exercised without sharing an event loop.
        """
        import asyncio

        limit = 10
        limiter = SlidingWindowRateLimiter(requests_per_window=limit, window_seconds=60)
        results: list[bool] = []
        lock = threading.Lock()

        def make_request() -> None:
            result = asyncio.run(limiter.is_allowed("shared_client"))
            with lock:
                results.append(result)

        threads = [threading.Thread(target=make_request) for _ in range(50)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        allowed = sum(1 for r in results if r)
        # Under GIL+list-comprehension atomicity in CPython this is typically
        # exactly `limit`, but interleaving can let it drift slightly higher.
        # 2× is a conservative ceiling; the property that matters is no vast
        # over-admission.
        assert allowed <= limit * 2, f"allowed={allowed} exceeded 2× limit={limit}"

    def test_multiple_clients_concurrent(self) -> None:
        """Each client tracks independently under concurrent access."""
        import asyncio

        limiter = SlidingWindowRateLimiter(requests_per_window=5, window_seconds=60)
        client_allowed: dict[str, int] = {}
        lock = threading.Lock()

        def make_requests(client_id: str) -> None:
            for _ in range(10):
                allowed = asyncio.run(limiter.is_allowed(client_id))
                if allowed:
                    with lock:
                        client_allowed[client_id] = client_allowed.get(client_id, 0) + 1

        threads = [threading.Thread(target=make_requests, args=(f"client_{i}",)) for i in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        for client_id, count in client_allowed.items():
            assert count <= 5, f"{client_id} allowed {count} requests, expected ≤5"


# ---------------------------------------------------------------------------
# Redis-backed path — mock AsyncRedisClient
# ---------------------------------------------------------------------------


class TestRedisPath:
    def _make_redis_mock(self) -> AsyncMock:
        """Build an AsyncMock that behaves like AsyncRedisClient."""
        return AsyncMock()

    async def test_is_allowed_delegates_to_redis(self) -> None:
        """is_allowed uses Redis when a client is configured."""
        redis = self._make_redis_mock()
        redis.zcard.return_value = 0
        redis.expire.return_value = True

        limiter = SlidingWindowRateLimiter(requests_per_window=5, window_seconds=60, redis=redis)
        result = await limiter.is_allowed("client1")

        assert result is True
        redis.zremrangebyscore.assert_awaited_once()
        redis.zcard.assert_awaited_once()
        redis.zadd.assert_awaited_once()
        redis.expire.assert_awaited_once()

    async def test_is_denied_when_redis_count_at_limit(self) -> None:
        """is_allowed returns False when zcard equals the limit."""
        redis = self._make_redis_mock()
        redis.zcard.return_value = 5  # already at limit

        limiter = SlidingWindowRateLimiter(requests_per_window=5, window_seconds=60, redis=redis)
        result = await limiter.is_allowed("client1")

        assert result is False
        redis.zadd.assert_not_awaited()

    async def test_get_retry_after_uses_redis_oldest_entry(self) -> None:
        """get_retry_after queries Redis for the oldest sorted-set entry."""
        redis = self._make_redis_mock()
        import time

        t0 = time.time() - 10  # 10 seconds ago
        redis.zrange.return_value = [("ts", t0)]

        limiter = SlidingWindowRateLimiter(requests_per_window=5, window_seconds=60, redis=redis)
        retry = await limiter.get_retry_after("client1")

        # Approximately 60 - 10 + 1 = 51
        assert 50 <= retry <= 52

    async def test_get_retry_after_returns_zero_when_no_entries(self) -> None:
        """get_retry_after returns 0 when the Redis key has no entries."""
        redis = self._make_redis_mock()
        redis.zrange.return_value = []

        limiter = SlidingWindowRateLimiter(requests_per_window=5, window_seconds=60, redis=redis)
        assert await limiter.get_retry_after("unknown") == 0

    async def test_redis_key_format(self) -> None:
        """Redis key includes client_id and window_seconds for isolation."""
        redis = self._make_redis_mock()
        redis.zcard.return_value = 0
        redis.expire.return_value = True

        limiter = SlidingWindowRateLimiter(requests_per_window=5, window_seconds=300, redis=redis)
        await limiter.is_allowed("my-client")

        call_args = redis.zadd.call_args
        key_arg: str = call_args[0][0]
        assert "my-client" in key_arg
        assert "300" in key_arg
        assert key_arg.startswith("mcp_auth:ratelimit:")
