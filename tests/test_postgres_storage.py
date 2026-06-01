"""Tests for PostgresTokenStorage timezone handling and error paths.

Asyncpg returns timezone-aware datetimes from TIMESTAMPTZ columns.
These tests verify that PostgresTokenStorage consistently uses
timezone-aware datetimes so comparisons don't raise TypeError.

Also covers error paths: initialize() pool creation, close() idempotency,
and RuntimeError guards for all methods called before initialize().
"""

from datetime import UTC, datetime, timedelta
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from mcp_authflow.storage.postgres import PostgresTokenStorage


def _get_datetime_args(call_args: tuple) -> list[datetime]:
    """Extract all datetime arguments from a mock call, regardless of position."""
    return [arg for arg in call_args[0] if isinstance(arg, datetime)]


def _make_storage() -> PostgresTokenStorage:
    """Create a PostgresTokenStorage with a mocked pool."""
    storage = PostgresTokenStorage(database_url="postgresql://test:test@localhost/test")
    storage._pool = MagicMock()
    return storage


def _mock_conn(fetchrow_return: dict | None = None, execute_return: str = "DELETE 0") -> MagicMock:
    """Create a mock asyncpg connection."""
    conn = AsyncMock()
    conn.fetchrow = AsyncMock(return_value=fetchrow_return)
    conn.execute = AsyncMock(return_value=execute_return)
    return conn


def _patch_pool(storage: PostgresTokenStorage, conn: MagicMock) -> None:
    """Patch storage._pool.acquire() to yield the mock connection."""
    ctx = AsyncMock()
    ctx.__aenter__ = AsyncMock(return_value=conn)
    ctx.__aexit__ = AsyncMock(return_value=False)
    storage._pool.acquire = MagicMock(return_value=ctx)  # type: ignore[union-attr]


class TestStoreTokenTimezone:
    """Verify store_token passes timezone-aware datetimes to the database."""

    @pytest.mark.asyncio
    async def test_store_token_passes_aware_datetime(self) -> None:
        storage = _make_storage()
        conn = _mock_conn()
        _patch_pool(storage, conn)

        expires_at = int(datetime.now(UTC).timestamp()) + 3600

        await storage.store_token(
            token="test_token",  # noqa: S106
            client_id="client1",
            scopes=["read"],
            expires_at=expires_at,
        )

        dt_args = _get_datetime_args(conn.execute.call_args)
        assert len(dt_args) > 0, "Expected at least one datetime arg passed to DB"
        for dt in dt_args:
            assert dt.tzinfo is not None, "All datetime args passed to DB must be timezone-aware"
            assert dt.tzinfo == UTC

    @pytest.mark.asyncio
    async def test_store_refresh_token_passes_aware_datetime(self) -> None:
        storage = _make_storage()
        conn = _mock_conn()
        _patch_pool(storage, conn)

        expires_at = int(datetime.now(UTC).timestamp()) + 86400

        await storage.store_refresh_token(
            refresh_token="test_refresh",  # noqa: S106
            client_id="client1",
            scopes=["read"],
            expires_at=expires_at,
        )

        dt_args = _get_datetime_args(conn.execute.call_args)
        assert len(dt_args) > 0, "Expected at least one datetime arg passed to DB"
        for dt in dt_args:
            assert dt.tzinfo is not None, "All datetime args passed to DB must be timezone-aware"
            assert dt.tzinfo == UTC


class TestLoadTokenTimezone:
    """Verify load_token handles timezone-aware datetimes from asyncpg.

    Asyncpg returns timezone-aware datetimes for TIMESTAMPTZ columns.
    These tests simulate that behavior and verify no TypeError is raised.
    """

    @pytest.mark.asyncio
    async def test_load_valid_token_with_aware_datetime(self) -> None:
        """Loading a non-expired token should succeed when DB returns aware datetimes."""
        storage = _make_storage()
        future = datetime.now(UTC) + timedelta(hours=1)
        created = datetime.now(UTC) - timedelta(hours=1)
        row = {
            "token": "test_token",
            "client_id": "client1",
            "scopes": "read write",
            "resource": None,
            "expires_at": future,
            "created_at": created,
            "user_id": 1,
        }
        conn = _mock_conn(fetchrow_return=row)
        _patch_pool(storage, conn)

        result = await storage.load_token("test_token")

        assert result is not None
        assert result["token"] == "test_token"  # noqa: S105
        assert result["scopes"] == ["read", "write"]

    @pytest.mark.asyncio
    async def test_load_expired_token_with_aware_datetime(self) -> None:
        """Loading an expired token should return None without raising TypeError."""
        storage = _make_storage()
        past = datetime.now(UTC) - timedelta(hours=1)
        created = datetime.now(UTC) - timedelta(hours=2)
        row = {
            "token": "expired_token",
            "client_id": "client1",
            "scopes": "read",
            "resource": None,
            "expires_at": past,
            "created_at": created,
            "user_id": 1,
        }
        conn = _mock_conn(fetchrow_return=row)
        _patch_pool(storage, conn)

        result = await storage.load_token("expired_token")

        assert result is None
        conn.execute.assert_called_once()  # delete was called

    @pytest.mark.asyncio
    async def test_load_token_not_found(self) -> None:
        storage = _make_storage()
        conn = _mock_conn(fetchrow_return=None)
        _patch_pool(storage, conn)

        result = await storage.load_token("nonexistent")

        assert result is None

    @pytest.mark.asyncio
    async def test_load_token_naive_datetime_would_fail(self) -> None:
        """Demonstrate that mixing naive DB datetimes with aware now() raises TypeError.

        This is the exact bug that was fixed. If someone reverts the fix in
        load_token to use datetime.utcnow() (naive), this test will catch it.
        """
        storage = _make_storage()
        # Simulate asyncpg returning a timezone-AWARE datetime (as TIMESTAMPTZ does)
        future_aware = datetime.now(UTC) + timedelta(hours=1)
        row = {
            "token": "test_token",
            "client_id": "client1",
            "scopes": "read",
            "resource": None,
            "expires_at": future_aware,
            "created_at": datetime.now(UTC),
            "user_id": 1,
        }
        conn = _mock_conn(fetchrow_return=row)
        _patch_pool(storage, conn)

        # This must NOT raise TypeError
        result = await storage.load_token("test_token")
        assert result is not None


class TestLoadRefreshTokenTimezone:
    """Same timezone tests for refresh tokens."""

    @pytest.mark.asyncio
    async def test_load_valid_refresh_token_with_aware_datetime(self) -> None:
        storage = _make_storage()
        future = datetime.now(UTC) + timedelta(days=7)
        created = datetime.now(UTC) - timedelta(hours=1)
        row = {
            "token": "refresh_token",
            "client_id": "client1",
            "scopes": "read write",
            "resource": "https://example.com",
            "expires_at": future,
            "created_at": created,
            "user_id": 1,
        }
        conn = _mock_conn(fetchrow_return=row)
        _patch_pool(storage, conn)

        result = await storage.load_refresh_token("refresh_token")

        assert result is not None
        assert result["token"] == "refresh_token"  # noqa: S105
        assert result["resource"] == "https://example.com"

    @pytest.mark.asyncio
    async def test_load_expired_refresh_token_with_aware_datetime(self) -> None:
        storage = _make_storage()
        past = datetime.now(UTC) - timedelta(days=1)
        created = datetime.now(UTC) - timedelta(days=8)
        row = {
            "token": "expired_refresh",
            "client_id": "client1",
            "scopes": "read",
            "resource": None,
            "expires_at": past,
            "created_at": created,
            "user_id": 1,
        }
        conn = _mock_conn(fetchrow_return=row)
        _patch_pool(storage, conn)

        result = await storage.load_refresh_token("expired_refresh")

        assert result is None
        conn.execute.assert_called_once()

    @pytest.mark.asyncio
    async def test_load_refresh_token_not_found(self) -> None:
        storage = _make_storage()
        conn = _mock_conn(fetchrow_return=None)
        _patch_pool(storage, conn)

        result = await storage.load_refresh_token("nonexistent")

        assert result is None


class TestCleanupTimezone:
    """Verify cleanup methods pass timezone-aware datetimes to SQL queries."""

    @pytest.mark.asyncio
    async def test_cleanup_expired_tokens_uses_aware_datetime(self) -> None:
        storage = _make_storage()
        conn = _mock_conn(execute_return="DELETE 3")
        _patch_pool(storage, conn)

        count = await storage.cleanup_expired_tokens()

        assert count == 3
        dt_args = _get_datetime_args(conn.execute.call_args)
        assert len(dt_args) == 1, "Expected exactly one datetime arg in cleanup query"
        assert dt_args[0].tzinfo is not None, (
            "now datetime passed to cleanup query must be timezone-aware"
        )

    @pytest.mark.asyncio
    async def test_cleanup_expired_refresh_tokens_uses_aware_datetime(self) -> None:
        storage = _make_storage()
        conn = _mock_conn(execute_return="DELETE 5")
        _patch_pool(storage, conn)

        count = await storage.cleanup_expired_refresh_tokens()

        assert count == 5
        dt_args = _get_datetime_args(conn.execute.call_args)
        assert len(dt_args) == 1, "Expected exactly one datetime arg in cleanup query"
        assert dt_args[0].tzinfo is not None, (
            "now datetime passed to cleanup query must be timezone-aware"
        )


class TestLoadTokenReturnFormat:
    """Verify load methods return correct data shapes."""

    @pytest.mark.asyncio
    async def test_load_token_returns_unix_timestamps(self) -> None:
        storage = _make_storage()
        future = datetime.now(UTC) + timedelta(hours=1)
        created = datetime(2026, 1, 1, 0, 0, 0, tzinfo=UTC)
        row = {
            "token": "tok",
            "client_id": "c1",
            "scopes": "read",
            "resource": None,
            "expires_at": future,
            "created_at": created,
            "user_id": 1,
        }
        conn = _mock_conn(fetchrow_return=row)
        _patch_pool(storage, conn)

        result = await storage.load_token("tok")

        assert result is not None
        assert isinstance(result["expires_at"], int)
        assert isinstance(result["created_at"], int)
        assert result["expires_at"] == int(future.timestamp())
        assert result["created_at"] == int(created.timestamp())

    @pytest.mark.asyncio
    async def test_load_token_empty_scopes(self) -> None:
        storage = _make_storage()
        future = datetime.now(UTC) + timedelta(hours=1)
        row = {
            "token": "tok",
            "client_id": "c1",
            "scopes": "",
            "resource": None,
            "expires_at": future,
            "created_at": datetime.now(UTC),
            "user_id": 1,
        }
        conn = _mock_conn(fetchrow_return=row)
        _patch_pool(storage, conn)

        result = await storage.load_token("tok")

        assert result is not None
        assert result["scopes"] == []

    @pytest.mark.asyncio
    async def test_load_token_null_created_at(self) -> None:
        storage = _make_storage()
        future = datetime.now(UTC) + timedelta(hours=1)
        row = {
            "token": "tok",
            "client_id": "c1",
            "scopes": "read",
            "resource": None,
            "expires_at": future,
            "created_at": None,
            "user_id": None,
        }
        conn = _mock_conn(fetchrow_return=row)
        _patch_pool(storage, conn)

        result = await storage.load_token("tok")

        assert result is not None
        assert result["created_at"] is None


class TestInitialize:
    """Tests for initialize() pool creation and error handling."""

    @pytest.mark.asyncio
    async def test_initialize_raises_when_no_database_url(self) -> None:
        """initialize() raises ValueError when database_url is not set."""
        storage = PostgresTokenStorage(database_url=None)
        # Ensure env var is not set
        with patch.dict("os.environ", {}, clear=True):
            storage.database_url = None
            with pytest.raises(ValueError, match="DATABASE_URL"):
                await storage.initialize()

    @pytest.mark.asyncio
    async def test_initialize_creates_pool(self) -> None:
        """initialize() calls asyncpg.create_pool with correct parameters."""
        storage = PostgresTokenStorage(database_url="postgresql://test:test@localhost/test")
        mock_pool = MagicMock()

        with patch("asyncpg.create_pool", new=AsyncMock(return_value=mock_pool)) as mock_create:
            await storage.initialize()

        mock_create.assert_awaited_once_with(
            "postgresql://test:test@localhost/test",
            min_size=2,
            max_size=10,
            command_timeout=30,
        )
        assert storage._pool is mock_pool


class TestClose:
    """Tests for close() idempotency."""

    @pytest.mark.asyncio
    async def test_close_when_pool_is_none_is_idempotent(self) -> None:
        """close() does nothing and does not raise when pool is None."""
        storage = PostgresTokenStorage(database_url="postgresql://test:test@localhost/test")
        assert storage._pool is None
        # Should not raise
        await storage.close()
        assert storage._pool is None

    @pytest.mark.asyncio
    async def test_close_when_pool_exists_closes_and_clears(self) -> None:
        """close() closes the pool and sets _pool to None."""
        storage = PostgresTokenStorage(database_url="postgresql://test:test@localhost/test")
        mock_pool = AsyncMock()
        storage._pool = mock_pool

        await storage.close()

        mock_pool.close.assert_awaited_once()
        assert storage._pool is None


class TestRuntimeErrorGuards:
    """Tests for RuntimeError raised when methods called before initialize()."""

    @pytest.mark.asyncio
    async def test_store_token_raises_when_not_initialized(self) -> None:
        """store_token raises RuntimeError when pool is None."""
        storage = PostgresTokenStorage(database_url="postgresql://test:test@localhost/test")
        with pytest.raises(RuntimeError, match="initialize"):
            await storage.store_token(
                token="tok",  # noqa: S106
                client_id="client1",
                scopes=["read"],
                expires_at=int(datetime.now(UTC).timestamp()) + 3600,
            )

    @pytest.mark.asyncio
    async def test_load_token_raises_when_not_initialized(self) -> None:
        """load_token raises RuntimeError when pool is None."""
        storage = PostgresTokenStorage(database_url="postgresql://test:test@localhost/test")
        with pytest.raises(RuntimeError, match="initialize"):
            await storage.load_token("tok")

    @pytest.mark.asyncio
    async def test_delete_token_raises_when_not_initialized(self) -> None:
        """delete_token raises RuntimeError when pool is None."""
        storage = PostgresTokenStorage(database_url="postgresql://test:test@localhost/test")
        with pytest.raises(RuntimeError, match="initialize"):
            await storage.delete_token("tok")

    @pytest.mark.asyncio
    async def test_cleanup_expired_tokens_raises_when_not_initialized(self) -> None:
        """cleanup_expired_tokens raises RuntimeError when pool is None."""
        storage = PostgresTokenStorage(database_url="postgresql://test:test@localhost/test")
        with pytest.raises(RuntimeError, match="initialize"):
            await storage.cleanup_expired_tokens()

    @pytest.mark.asyncio
    async def test_get_token_count_raises_when_not_initialized(self) -> None:
        """get_token_count raises RuntimeError when pool is None."""
        storage = PostgresTokenStorage(database_url="postgresql://test:test@localhost/test")
        with pytest.raises(RuntimeError, match="initialize"):
            await storage.get_token_count()

    @pytest.mark.asyncio
    async def test_store_refresh_token_raises_when_not_initialized(self) -> None:
        """store_refresh_token raises RuntimeError when pool is None."""
        storage = PostgresTokenStorage(database_url="postgresql://test:test@localhost/test")
        with pytest.raises(RuntimeError, match="initialize"):
            await storage.store_refresh_token(
                refresh_token="ref",  # noqa: S106
                client_id="client1",
                scopes=["read"],
                expires_at=int(datetime.now(UTC).timestamp()) + 86400,
            )

    @pytest.mark.asyncio
    async def test_load_refresh_token_raises_when_not_initialized(self) -> None:
        """load_refresh_token raises RuntimeError when pool is None."""
        storage = PostgresTokenStorage(database_url="postgresql://test:test@localhost/test")
        with pytest.raises(RuntimeError, match="initialize"):
            await storage.load_refresh_token("ref")

    @pytest.mark.asyncio
    async def test_delete_refresh_token_raises_when_not_initialized(self) -> None:
        """delete_refresh_token raises RuntimeError when pool is None."""
        storage = PostgresTokenStorage(database_url="postgresql://test:test@localhost/test")
        with pytest.raises(RuntimeError, match="initialize"):
            await storage.delete_refresh_token("ref")

    @pytest.mark.asyncio
    async def test_cleanup_expired_refresh_tokens_raises_when_not_initialized(self) -> None:
        """cleanup_expired_refresh_tokens raises RuntimeError when pool is None."""
        storage = PostgresTokenStorage(database_url="postgresql://test:test@localhost/test")
        with pytest.raises(RuntimeError, match="initialize"):
            await storage.cleanup_expired_refresh_tokens()


class TestGetTokenCount:
    """Tests for get_token_count()."""

    @pytest.mark.asyncio
    async def test_get_token_count_returns_count(self) -> None:
        """get_token_count returns integer count from DB."""
        storage = _make_storage()
        row = {"count": 42}
        conn = _mock_conn(fetchrow_return=row)
        _patch_pool(storage, conn)

        count = await storage.get_token_count()

        assert count == 42

    @pytest.mark.asyncio
    async def test_get_token_count_returns_zero_when_no_row(self) -> None:
        """get_token_count returns 0 when DB returns None."""
        storage = _make_storage()
        conn = _mock_conn(fetchrow_return=None)
        _patch_pool(storage, conn)

        count = await storage.get_token_count()

        assert count == 0
