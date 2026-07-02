"""In-memory token storage implementation for testing."""

import logging
import time
from typing import Any

from mcp_authflow.storage.base import TokenStorage, token_fingerprint

logger = logging.getLogger(__name__)


class MemoryTokenStorage(TokenStorage):
    """In-memory token storage for testing and development.

    This implementation stores tokens in memory and does not persist them
    across restarts. Suitable for testing and development only.
    """

    def __init__(self) -> None:
        """Initialize in-memory token storage."""
        self._access_tokens: dict[str, dict[str, Any]] = {}
        self._refresh_tokens: dict[str, dict[str, Any]] = {}
        self._initialized = False

    async def initialize(self) -> None:
        """Initialize the storage (no-op for memory storage)."""
        logger.info("Initializing in-memory token storage")
        self._initialized = True

    async def close(self) -> None:
        """Close the storage and clear all tokens."""
        logger.info("Closing in-memory token storage")
        self._access_tokens.clear()
        self._refresh_tokens.clear()
        self._initialized = False

    def _require_initialized(self) -> None:
        """Raise if the storage has not been initialized yet."""
        if not self._initialized:
            raise RuntimeError("Token storage not initialized. Call initialize() first.")

    def _store_to(
        self,
        store: dict[str, dict[str, Any]],
        token: str,
        client_id: str,
        scopes: list[str],
        expires_at: int,
        resource: str | None,
        user_id: int | None,
        label: str,
    ) -> None:
        """Store a token record into the given dict."""
        self._require_initialized()
        store[token] = {
            "token": token,
            "client_id": client_id,
            "scopes": scopes.copy(),
            "resource": resource,
            "expires_at": expires_at,
            "created_at": int(time.time()),
            "user_id": user_id,
        }
        logger.debug("Stored %s %s for client %s", label, token_fingerprint(token), client_id)

    async def _load_from(
        self,
        store: dict[str, dict[str, Any]],
        token: str,
        label: str,
    ) -> dict[str, Any] | None:
        """Load a token record from the given dict, dropping it if expired."""
        self._require_initialized()

        token_data = store.get(token)
        if not token_data:
            logger.debug("%s %s not found in memory", label.capitalize(), token_fingerprint(token))
            return None

        now = int(time.time())
        if token_data["expires_at"] < now:
            logger.debug("%s %s has expired", label.capitalize(), token_fingerprint(token))
            self._delete_from(store, token, label)
            return None

        return token_data.copy()

    def _delete_from(self, store: dict[str, dict[str, Any]], token: str, label: str) -> None:
        """Delete a token record from the given dict."""
        self._require_initialized()

        if token in store:
            del store[token]
            logger.debug("Deleted %s %s", label, token_fingerprint(token))

    def _cleanup_from(self, store: dict[str, dict[str, Any]], label: str) -> int:
        """Remove all expired token records from the given dict."""
        self._require_initialized()

        now = int(time.time())
        expired_tokens = [token for token, data in store.items() if data["expires_at"] < now]

        for token in expired_tokens:
            del store[token]

        count = len(expired_tokens)
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
        """Store an access token in memory.

        Args:
            token: The access token string
            client_id: OAuth client ID
            scopes: List of granted scopes
            expires_at: Unix timestamp when token expires
            resource: Optional RFC 8707 resource binding
            user_id: Optional ID of the user who authorized the token
        """
        self._store_to(
            self._access_tokens, token, client_id, scopes, expires_at, resource, user_id, "token"
        )

    async def load_token(self, token: str) -> dict[str, Any] | None:
        """Load an access token from memory.

        Args:
            token: The access token string to look up

        Returns:
            Token data dict if found and not expired, None otherwise
        """
        return await self._load_from(self._access_tokens, token, "token")

    async def delete_token(self, token: str) -> None:
        """Delete a token from memory.

        Args:
            token: The access token string to delete
        """
        self._delete_from(self._access_tokens, token, "token")

    async def cleanup_expired_tokens(self) -> int:
        """Remove all expired access tokens from memory.

        Returns:
            Number of tokens removed
        """
        return self._cleanup_from(self._access_tokens, "token")

    async def get_token_count(self) -> int:
        """Get the total number of access tokens in storage.

        Returns:
            Number of tokens stored
        """
        self._require_initialized()
        return len(self._access_tokens)

    async def store_refresh_token(
        self,
        refresh_token: str,
        client_id: str,
        scopes: list[str],
        expires_at: int,
        resource: str | None = None,
        user_id: int | None = None,
    ) -> None:
        """Store a refresh token in memory.

        Args:
            refresh_token: The refresh token string
            client_id: OAuth client ID
            scopes: List of granted scopes
            expires_at: Unix timestamp when token expires
            resource: Optional RFC 8707 resource binding
            user_id: Optional ID of the user who authorized the token
        """
        self._store_to(
            self._refresh_tokens,
            refresh_token,
            client_id,
            scopes,
            expires_at,
            resource,
            user_id,
            "refresh token",
        )

    async def load_refresh_token(self, refresh_token: str) -> dict[str, Any] | None:
        """Load a refresh token from memory.

        Args:
            refresh_token: The refresh token string to look up

        Returns:
            Token data dict if found and not expired, None otherwise
        """
        return await self._load_from(self._refresh_tokens, refresh_token, "refresh token")

    async def delete_refresh_token(self, refresh_token: str) -> None:
        """Delete a refresh token from memory.

        Args:
            refresh_token: The refresh token string to delete
        """
        self._delete_from(self._refresh_tokens, refresh_token, "refresh token")

    async def cleanup_expired_refresh_tokens(self) -> int:
        """Remove all expired refresh tokens from memory.

        Returns:
            Number of tokens removed
        """
        return self._cleanup_from(self._refresh_tokens, "refresh token")
