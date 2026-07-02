"""PostgreSQL-backed token storage implementation.

Requires the ``postgres`` extra: ``pip install mcp-authflow[postgres]``
"""

import logging
import os
from datetime import UTC, datetime
from typing import Any

try:
    import asyncpg
except ImportError as _exc:
    raise ImportError(
        "PostgresTokenStorage requires asyncpg. Install it with: pip install mcp-authflow[postgres]"
    ) from _exc

from mcp_authflow.storage.base import TokenStorage, token_fingerprint

logger = logging.getLogger(__name__)


class PostgresTokenStorage(TokenStorage):
    """Database-backed storage for MCP access tokens using PostgreSQL."""

    def __init__(self, database_url: str | None = None):
        """Initialize token storage.

        Args:
            database_url: PostgreSQL connection URL. If not provided,
                         will be read from DATABASE_URL environment variable.
        """
        self.database_url = database_url or os.environ.get("DATABASE_URL")
        self._pool: asyncpg.Pool | None = None

    async def initialize(self) -> None:
        """Initialize the database connection pool."""
        if not self.database_url:
            raise ValueError("DATABASE_URL environment variable is required for token storage")

        logger.info("Initializing database connection pool for token storage")
        self._pool = await asyncpg.create_pool(
            self.database_url,
            min_size=2,
            max_size=10,
            command_timeout=30,
        )
        logger.info("Database connection pool initialized")

    async def close(self) -> None:
        """Close the database connection pool."""
        if self._pool:
            await self._pool.close()
            self._pool = None
            logger.info("Database connection pool closed")

    def _require_pool(self) -> "asyncpg.Pool":
        """Return the connection pool, raising if the storage is not initialized."""
        if not self._pool:
            raise RuntimeError("Token storage not initialized. Call initialize() first.")
        return self._pool

    async def _store_to(
        self,
        table: str,
        token: str,
        client_id: str,
        scopes: list[str],
        expires_at: int,
        resource: str | None,
        user_id: int | None,
        label: str,
    ) -> None:
        """Insert or update a token record in the given table."""
        pool = self._require_pool()

        expires_datetime = datetime.fromtimestamp(expires_at, tz=UTC)
        scopes_str = " ".join(scopes)

        # ``table`` is always an internal literal (see the public wrappers below),
        # never caller-supplied, so the interpolation is not an injection vector.
        query = f"""
            INSERT INTO {table}
                (token, client_id, scopes, resource, expires_at, user_id)
            VALUES ($1, $2, $3, $4, $5, $6)
            ON CONFLICT (token) DO UPDATE SET
                client_id = EXCLUDED.client_id,
                scopes = EXCLUDED.scopes,
                resource = EXCLUDED.resource,
                expires_at = EXCLUDED.expires_at,
                user_id = EXCLUDED.user_id
        """  # nosec B608
        async with pool.acquire() as conn:
            await conn.execute(
                query,
                token,
                client_id,
                scopes_str,
                resource,
                expires_datetime,
                user_id,
            )
        logger.debug("Stored %s %s for client %s", label, token_fingerprint(token), client_id)

    async def _load_from(self, table: str, token: str, label: str) -> dict[str, Any] | None:
        """Load a token record from the given table, dropping it if expired."""
        pool = self._require_pool()

        # ``table`` is always an internal literal (see the public wrappers below).
        query = f"""
            SELECT token, client_id, scopes, resource, expires_at, created_at, user_id
            FROM {table}
            WHERE token = $1
        """  # nosec B608
        async with pool.acquire() as conn:
            row = await conn.fetchrow(query, token)

        if not row:
            logger.debug(
                "%s %s not found in database", label.capitalize(), token_fingerprint(token)
            )
            return None

        # Check if expired
        expires_at = row["expires_at"]
        now = datetime.now(UTC)
        if expires_at < now:
            logger.debug("%s %s has expired", label.capitalize(), token_fingerprint(token))
            await self._delete_from(table, token, label)
            return None

        return {
            "token": row["token"],
            "client_id": row["client_id"],
            "scopes": row["scopes"].split() if row["scopes"] else [],
            "resource": row["resource"],
            "expires_at": int(expires_at.timestamp()),
            "created_at": int(row["created_at"].timestamp()) if row["created_at"] else None,
            "user_id": row["user_id"],
        }

    async def _delete_from(self, table: str, token: str, label: str) -> None:
        """Delete a token record from the given table."""
        pool = self._require_pool()

        # ``table`` is always an internal literal (see the public wrappers below).
        query = f"DELETE FROM {table} WHERE token = $1"  # nosec B608
        async with pool.acquire() as conn:
            await conn.execute(query, token)
        logger.debug("Deleted %s %s", label, token_fingerprint(token))

    async def _cleanup_from(self, table: str, label: str) -> int:
        """Remove all expired token records from the given table."""
        pool = self._require_pool()

        now = datetime.now(UTC)
        # ``table`` is always an internal literal (see the public wrappers below).
        query = f"DELETE FROM {table} WHERE expires_at < $1"  # nosec B608
        async with pool.acquire() as conn:
            result = await conn.execute(query, now)
        # Parse the DELETE count from result string like "DELETE 5"
        count = int(result.split()[-1]) if result else 0
        if count > 0:
            logger.info("Cleaned up %s expired %ss", count, label)
        return count

    async def store_token(
        self,
        token: str,
        client_id: str,
        scopes: list[str],
        expires_at: int,
        resource: str | None = None,
        user_id: int | None = None,
    ) -> None:
        """Store an access token in the database.

        Args:
            token: The access token string
            client_id: OAuth client ID
            scopes: List of granted scopes
            expires_at: Unix timestamp when token expires
            resource: Optional RFC 8707 resource binding
            user_id: Optional ID of the user who authorized the token
        """
        await self._store_to(
            "mcp_access_tokens",
            token,
            client_id,
            scopes,
            expires_at,
            resource,
            user_id,
            "token",
        )

    async def load_token(self, token: str) -> dict[str, Any] | None:
        """Load an access token from the database.

        Args:
            token: The access token string to look up

        Returns:
            Token data dict if found and not expired, None otherwise
        """
        return await self._load_from("mcp_access_tokens", token, "token")

    async def delete_token(self, token: str) -> None:
        """Delete a token from the database.

        Args:
            token: The access token string to delete
        """
        await self._delete_from("mcp_access_tokens", token, "token")

    async def cleanup_expired_tokens(self) -> int:
        """Remove all expired tokens from the database.

        Returns:
            Number of tokens removed
        """
        return await self._cleanup_from("mcp_access_tokens", "token")

    async def get_token_count(self) -> int:
        """Get the total number of tokens in storage.

        Returns:
            Number of tokens stored
        """
        pool = self._require_pool()

        async with pool.acquire() as conn:
            row = await conn.fetchrow("SELECT COUNT(*) as count FROM mcp_access_tokens")
        return row["count"] if row else 0

    async def store_refresh_token(
        self,
        refresh_token: str,
        client_id: str,
        scopes: list[str],
        expires_at: int,
        resource: str | None = None,
        user_id: int | None = None,
    ) -> None:
        """Store a refresh token in the database.

        Args:
            refresh_token: The refresh token string
            client_id: OAuth client ID
            scopes: List of granted scopes
            expires_at: Unix timestamp when token expires
            resource: Optional RFC 8707 resource binding
            user_id: Optional ID of the user who authorized the token
        """
        await self._store_to(
            "mcp_refresh_tokens",
            refresh_token,
            client_id,
            scopes,
            expires_at,
            resource,
            user_id,
            "refresh token",
        )

    async def load_refresh_token(self, refresh_token: str) -> dict[str, Any] | None:
        """Load a refresh token from the database.

        Args:
            refresh_token: The refresh token string to look up

        Returns:
            Token data dict if found and not expired, None otherwise
        """
        return await self._load_from("mcp_refresh_tokens", refresh_token, "refresh token")

    async def delete_refresh_token(self, refresh_token: str) -> None:
        """Delete a refresh token from the database.

        Args:
            refresh_token: The refresh token string to delete
        """
        await self._delete_from("mcp_refresh_tokens", refresh_token, "refresh token")

    async def cleanup_expired_refresh_tokens(self) -> int:
        """Remove all expired refresh tokens from the database.

        Returns:
            Number of tokens removed
        """
        return await self._cleanup_from("mcp_refresh_tokens", "refresh token")
