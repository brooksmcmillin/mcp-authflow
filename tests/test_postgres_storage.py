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

from mcp_authflow.storage.base import hash_token
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


def _patch_pool_on(pool: MagicMock, conn: MagicMock) -> None:
    """Patch a mock pool's acquire() to yield the mock connection."""
    ctx = AsyncMock()
    ctx.__aenter__ = AsyncMock(return_value=conn)
    ctx.__aexit__ = AsyncMock(return_value=False)
    pool.acquire = MagicMock(return_value=ctx)


def _patch_pool(storage: PostgresTokenStorage, conn: MagicMock) -> None:
    """Patch storage._pool.acquire() to yield the mock connection."""
    _patch_pool_on(storage._pool, conn)  # type: ignore[arg-type]


# The columns the documented DDL defines for each token table.
_ALL_COLUMNS = ("token", "client_id", "scopes", "resource", "expires_at", "created_at", "user_id")


def _schema_rows(
    access_columns: tuple[str, ...] = _ALL_COLUMNS,
    refresh_columns: tuple[str, ...] = _ALL_COLUMNS,
) -> list[dict[str, str]]:
    """Build information_schema.columns rows for the token tables."""
    rows: list[dict[str, str]] = []
    for column in access_columns:
        rows.append({"table_name": "mcp_access_tokens", "column_name": column})
    for column in refresh_columns:
        rows.append({"table_name": "mcp_refresh_tokens", "column_name": column})
    return rows


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


class TestUserIdPassThrough:
    """user_id is stored and returned verbatim, so UUID/TEXT columns work too."""

    _UUID = "5f7c9d3e-1b2a-4c6d-8e9f-0a1b2c3d4e5f"

    @pytest.mark.asyncio
    async def test_store_token_passes_string_user_id_unchanged(self) -> None:
        storage = _make_storage()
        conn = _mock_conn()
        _patch_pool(storage, conn)

        await storage.store_token(
            token="test_token",  # noqa: S106
            client_id="client1",
            scopes=["read"],
            expires_at=int(datetime.now(UTC).timestamp()) + 3600,
            user_id=self._UUID,
        )

        assert self._UUID in conn.execute.call_args[0]

    @pytest.mark.asyncio
    async def test_store_refresh_token_passes_string_user_id_unchanged(self) -> None:
        storage = _make_storage()
        conn = _mock_conn()
        _patch_pool(storage, conn)

        await storage.store_refresh_token(
            refresh_token="test_refresh",  # noqa: S106
            client_id="client1",
            scopes=["read"],
            expires_at=int(datetime.now(UTC).timestamp()) + 86400,
            user_id=self._UUID,
        )

        assert self._UUID in conn.execute.call_args[0]

    @pytest.mark.asyncio
    async def test_load_token_returns_string_user_id(self) -> None:
        storage = _make_storage()
        row = {
            "token": "test_token",
            "client_id": "client1",
            "scopes": "read",
            "resource": None,
            "expires_at": datetime.now(UTC) + timedelta(hours=1),
            "created_at": datetime.now(UTC),
            "user_id": self._UUID,
        }
        conn = _mock_conn(fetchrow_return=row)
        _patch_pool(storage, conn)

        result = await storage.load_token("test_token")

        assert result is not None
        assert result["user_id"] == self._UUID


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

    @pytest.mark.asyncio
    async def test_cleanup_expired_tokens_returns_zero_when_nothing_deleted(self) -> None:
        storage = _make_storage()
        conn = _mock_conn(execute_return="DELETE 0")
        _patch_pool(storage, conn)

        assert await storage.cleanup_expired_tokens() == 0

    @pytest.mark.asyncio
    async def test_cleanup_expired_refresh_tokens_returns_zero_when_nothing_deleted(self) -> None:
        storage = _make_storage()
        conn = _mock_conn(execute_return="DELETE 0")
        _patch_pool(storage, conn)

        assert await storage.cleanup_expired_refresh_tokens() == 0


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


class TestTokenHashedAtRest:
    """Verify tokens are persisted and looked up by digest, never as plaintext."""

    @pytest.mark.asyncio
    async def test_store_token_persists_digest_not_plaintext(self) -> None:
        storage = _make_storage()
        conn = _mock_conn()
        _patch_pool(storage, conn)

        await storage.store_token(
            token="secret-access",  # noqa: S106
            client_id="client1",
            scopes=["read"],
            expires_at=int(datetime.now(UTC).timestamp()) + 3600,
        )

        args = conn.execute.call_args[0]
        assert args[1] == hash_token("secret-access")
        assert "secret-access" not in args

    @pytest.mark.asyncio
    async def test_store_refresh_token_persists_digest_not_plaintext(self) -> None:
        storage = _make_storage()
        conn = _mock_conn()
        _patch_pool(storage, conn)

        await storage.store_refresh_token(
            refresh_token="secret-refresh",  # noqa: S106
            client_id="client1",
            scopes=["read"],
            expires_at=int(datetime.now(UTC).timestamp()) + 86400,
        )

        args = conn.execute.call_args[0]
        assert args[1] == hash_token("secret-refresh")
        assert "secret-refresh" not in args

    @pytest.mark.asyncio
    async def test_load_token_looks_up_by_digest(self) -> None:
        storage = _make_storage()
        future = datetime.now(UTC) + timedelta(hours=1)
        row = {
            "client_id": "client1",
            "scopes": "read",
            "resource": None,
            "expires_at": future,
            "created_at": datetime.now(UTC),
            "user_id": 1,
        }
        conn = _mock_conn(fetchrow_return=row)
        _patch_pool(storage, conn)

        result = await storage.load_token("secret-access")

        # Lookup happens on the digest, never the raw token.
        assert conn.fetchrow.call_args[0][1] == hash_token("secret-access")
        # The raw token the caller passed is echoed back, not the stored digest.
        assert result is not None
        assert result["token"] == "secret-access"  # noqa: S105

    @pytest.mark.asyncio
    async def test_delete_token_targets_digest(self) -> None:
        storage = _make_storage()
        conn = _mock_conn()
        _patch_pool(storage, conn)

        await storage.delete_token("secret-access")

        assert conn.execute.call_args[0][1] == hash_token("secret-access")


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
        # initialize() runs a schema check after creating the pool; return a
        # fully-populated schema so it passes.
        conn = _mock_conn()
        conn.fetch = AsyncMock(return_value=_schema_rows())
        _patch_pool_on(mock_pool, conn)

        with patch("asyncpg.create_pool", new=AsyncMock(return_value=mock_pool)) as mock_create:
            await storage.initialize()

        mock_create.assert_awaited_once_with(
            "postgresql://test:test@localhost/test",
            min_size=2,
            max_size=10,
            command_timeout=30,
        )
        assert storage._pool is mock_pool


class TestVerifySchema:
    """Tests for the information_schema drift check run during initialize()."""

    @pytest.mark.asyncio
    async def test_passes_when_all_columns_present(self) -> None:
        """A fully-populated schema does not raise."""
        storage = _make_storage()
        conn = _mock_conn()
        conn.fetch = AsyncMock(return_value=_schema_rows())
        _patch_pool(storage, conn)

        await storage._verify_schema()  # should not raise

    @pytest.mark.asyncio
    async def test_raises_when_column_missing(self) -> None:
        """A table missing a required column fails fast, naming table and column."""
        storage = _make_storage()
        conn = _mock_conn()
        drifted = tuple(c for c in _ALL_COLUMNS if c != "user_id")
        conn.fetch = AsyncMock(return_value=_schema_rows(access_columns=drifted))
        _patch_pool(storage, conn)

        with pytest.raises(RuntimeError, match="schema is out of date") as exc_info:
            await storage._verify_schema()

        message = str(exc_info.value)
        assert "mcp_access_tokens" in message
        assert "user_id" in message
        assert "ALTER TABLE" in message

    @pytest.mark.asyncio
    async def test_skips_tables_that_do_not_exist(self) -> None:
        """A table with no rows in information_schema is treated as not-yet-created."""
        storage = _make_storage()
        conn = _mock_conn()
        # Only the access-token table exists; the refresh table is optional.
        conn.fetch = AsyncMock(return_value=_schema_rows(refresh_columns=()))
        _patch_pool(storage, conn)

        await storage._verify_schema()  # should not raise

    @pytest.mark.asyncio
    async def test_reports_multiple_missing_columns(self) -> None:
        """All missing columns across both tables are reported together."""
        storage = _make_storage()
        conn = _mock_conn()
        conn.fetch = AsyncMock(
            return_value=_schema_rows(
                access_columns=("token", "client_id", "scopes", "expires_at", "created_at"),
                refresh_columns=("token", "client_id", "scopes", "resource", "created_at"),
            )
        )
        _patch_pool(storage, conn)

        with pytest.raises(RuntimeError) as exc_info:
            await storage._verify_schema()

        message = str(exc_info.value)
        assert "resource" in message
        assert "user_id" in message
        assert "expires_at" in message


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

    @pytest.mark.asyncio
    async def test_get_refresh_token_count_raises_when_not_initialized(self) -> None:
        """get_refresh_token_count raises RuntimeError when pool is None."""
        storage = PostgresTokenStorage(database_url="postgresql://test:test@localhost/test")
        with pytest.raises(RuntimeError, match="initialize"):
            await storage.get_refresh_token_count()

    @pytest.mark.asyncio
    async def test_get_refresh_token_count_returns_count(self) -> None:
        """get_refresh_token_count returns integer count from DB."""
        storage = _make_storage()
        conn = _mock_conn(fetchrow_return={"count": 7})
        _patch_pool(storage, conn)

        count = await storage.get_refresh_token_count()

        assert count == 7

    @pytest.mark.asyncio
    async def test_get_refresh_token_count_returns_zero_when_no_row(self) -> None:
        """get_refresh_token_count returns 0 when DB returns None."""
        storage = _make_storage()
        conn = _mock_conn(fetchrow_return=None)
        _patch_pool(storage, conn)

        count = await storage.get_refresh_token_count()

        assert count == 0
