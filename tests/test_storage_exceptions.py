"""Tests for the token-storage exception taxonomy.

The taxonomy exists so a server can tell a *misconfiguration* (which retrying
never fixes, and which should stop startup) apart from a *transient* database
problem (which may warrant degrading or retrying). Before it existed both
arrived as bare ``RuntimeError`` / ``ValueError``, so the two were only
distinguishable by matching on the message text.

These tests pin both halves of that contract: the new classes are raised where
the misconfigurations occur, and they still satisfy the builtin ``except``
clauses that callers written against earlier releases use.
"""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

import mcp_authflow
from mcp_authflow.storage import (
    MemoryTokenStorage,
    SchemaDriftError,
    StorageConfigError,
    StorageError,
    StorageNotInitializedError,
)
from mcp_authflow.storage.postgres import PostgresTokenStorage

_ALL_COLUMNS = ("token", "client_id", "scopes", "resource", "expires_at", "created_at", "user_id")


def _schema_rows(access_columns: tuple[str, ...] = _ALL_COLUMNS) -> list[dict[str, str]]:
    """Build information_schema.columns rows for the token tables."""
    rows = [{"table_name": "mcp_access_tokens", "column_name": c} for c in access_columns]
    rows += [{"table_name": "mcp_refresh_tokens", "column_name": c} for c in _ALL_COLUMNS]
    return rows


class TestHierarchy:
    """The classes compose so callers can catch broadly or narrowly."""

    @pytest.mark.parametrize(
        "error",
        [SchemaDriftError, StorageConfigError, StorageNotInitializedError],
    )
    def test_every_storage_fault_derives_from_the_base(self, error: type[Exception]) -> None:
        assert issubclass(error, StorageError)

    @pytest.mark.parametrize(
        ("error", "legacy"),
        [
            (StorageConfigError, ValueError),
            (SchemaDriftError, RuntimeError),
            (StorageNotInitializedError, RuntimeError),
        ],
    )
    def test_legacy_builtin_still_catches_each_fault(
        self, error: type[Exception], legacy: type[Exception]
    ) -> None:
        """Callers written against <=0.8.0 keep working unchanged."""
        assert issubclass(error, legacy)

        with pytest.raises(legacy):
            raise error("boom")

    def test_storage_error_does_not_swallow_transient_failures(self) -> None:
        """The point of the taxonomy: driver/OS errors are NOT StorageError.

        A caller that degrades on ``StorageError`` and re-raises everything else
        (or the reverse) depends on these two groups staying disjoint.
        """
        assert not issubclass(OSError, StorageError)
        assert not issubclass(ConnectionRefusedError, StorageError)

        with pytest.raises(OSError):
            try:
                raise ConnectionRefusedError("database unreachable")
            except StorageError:  # pragma: no cover - must not catch
                pytest.fail("StorageError caught a transient connection failure")

    @pytest.mark.parametrize(
        "name",
        ["SchemaDriftError", "StorageConfigError", "StorageError", "StorageNotInitializedError"],
    )
    def test_exported_from_package_root(self, name: str) -> None:
        """Importable as ``from mcp_authflow import ...`` without the postgres extra."""
        assert name in mcp_authflow.__all__
        assert getattr(mcp_authflow, name) is not None


class TestPostgresRaisesTaxonomy:
    """PostgresTokenStorage reports each misconfiguration with its own class."""

    @pytest.mark.asyncio
    async def test_missing_database_url_raises_config_error(self) -> None:
        storage = PostgresTokenStorage(database_url=None)
        with patch.dict("os.environ", {}, clear=True):
            storage.database_url = None
            with pytest.raises(StorageConfigError, match="DATABASE_URL"):
                await storage.initialize()

    @pytest.mark.asyncio
    async def test_schema_drift_raises_schema_drift_error(self) -> None:
        storage = PostgresTokenStorage(database_url="postgresql://test:test@localhost/test")
        storage._pool = MagicMock()
        conn = AsyncMock()
        conn.fetch = AsyncMock(
            return_value=_schema_rows(tuple(c for c in _ALL_COLUMNS if c != "user_id"))
        )
        storage._pool.acquire.return_value.__aenter__ = AsyncMock(return_value=conn)
        storage._pool.acquire.return_value.__aexit__ = AsyncMock(return_value=False)

        with pytest.raises(SchemaDriftError, match="schema is out of date"):
            await storage._verify_schema()

    @pytest.mark.asyncio
    async def test_use_before_initialize_raises_not_initialized(self) -> None:
        storage = PostgresTokenStorage(database_url="postgresql://test:test@localhost/test")

        with pytest.raises(StorageNotInitializedError, match="initialize"):
            await storage.load_token("some-token")


class TestMemoryRaisesTaxonomy:
    """MemoryTokenStorage shares the lifecycle guard."""

    @pytest.mark.asyncio
    async def test_use_before_initialize_raises_not_initialized(self) -> None:
        storage = MemoryTokenStorage()

        with pytest.raises(StorageNotInitializedError, match="initialize"):
            await storage.load_token("some-token")


class TestCallerPattern:
    """The branch the taxonomy was added to make expressible."""

    @pytest.mark.asyncio
    async def test_misconfiguration_is_distinguishable_from_an_outage(self) -> None:
        async def start(storage_error: Exception) -> str:
            try:
                raise storage_error
            except StorageError:
                return "abort startup"
            except (OSError, ConnectionError):
                return "degrade"

        assert await start(SchemaDriftError("drift")) == "abort startup"
        assert await start(StorageConfigError("no url")) == "abort startup"
        assert await start(ConnectionRefusedError("db down")) == "degrade"
