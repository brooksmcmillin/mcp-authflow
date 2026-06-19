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
        if not self._initialized:
            raise RuntimeError("Token storage not initialized. Call initialize() first.")

        self._access_tokens[token] = {
            "token": token,
            "client_id": client_id,
            "scopes": scopes.copy(),
            "resource": resource,
            "expires_at": expires_at,
            "created_at": int(time.time()),
            "user_id": user_id,
        }
        logger.debug("Stored token %s for client %s", token_fingerprint(token), client_id)

    async def load_token(self, token: str) -> dict[str, Any] | None:
        """Load an access token from memory.

        Args:
            token: The access token string to look up

        Returns:
            Token data dict if found and not expired, None otherwise
        """
        if not self._initialized:
            raise RuntimeError("Token storage not initialized. Call initialize() first.")

        token_data = self._access_tokens.get(token)
        if not token_data:
            logger.debug("Token %s not found in memory", token_fingerprint(token))
            return None

        # Check if expired
        now = int(time.time())
        if token_data["expires_at"] < now:
            logger.debug("Token %s has expired", token_fingerprint(token))
            await self.delete_token(token)
            return None

        return token_data.copy()

    async def delete_token(self, token: str) -> None:
        """Delete a token from memory.

        Args:
            token: The access token string to delete
        """
        if not self._initialized:
            raise RuntimeError("Token storage not initialized. Call initialize() first.")

        if token in self._access_tokens:
            del self._access_tokens[token]
            logger.debug("Deleted token %s", token_fingerprint(token))

    async def cleanup_expired_tokens(self) -> int:
        """Remove all expired access tokens from memory.

        Returns:
            Number of tokens removed
        """
        if not self._initialized:
            raise RuntimeError("Token storage not initialized. Call initialize() first.")

        now = int(time.time())
        expired_tokens = [
            token for token, data in self._access_tokens.items() if data["expires_at"] < now
        ]

        for token in expired_tokens:
            del self._access_tokens[token]

        count = len(expired_tokens)
        if count > 0:
            logger.info("Cleaned up %s expired tokens", count)
        return count

    async def get_token_count(self) -> int:
        """Get the total number of access tokens in storage.

        Returns:
            Number of tokens stored
        """
        if not self._initialized:
            raise RuntimeError("Token storage not initialized. Call initialize() first.")

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
        if not self._initialized:
            raise RuntimeError("Token storage not initialized. Call initialize() first.")

        self._refresh_tokens[refresh_token] = {
            "token": refresh_token,
            "client_id": client_id,
            "scopes": scopes.copy(),
            "resource": resource,
            "expires_at": expires_at,
            "created_at": int(time.time()),
            "user_id": user_id,
        }
        logger.debug(
            "Stored refresh token %s for client %s", token_fingerprint(refresh_token), client_id
        )

    async def load_refresh_token(self, refresh_token: str) -> dict[str, Any] | None:
        """Load a refresh token from memory.

        Args:
            refresh_token: The refresh token string to look up

        Returns:
            Token data dict if found and not expired, None otherwise
        """
        if not self._initialized:
            raise RuntimeError("Token storage not initialized. Call initialize() first.")

        token_data = self._refresh_tokens.get(refresh_token)
        if not token_data:
            logger.debug("Refresh token %s not found in memory", token_fingerprint(refresh_token))
            return None

        # Check if expired
        now = int(time.time())
        if token_data["expires_at"] < now:
            logger.debug("Refresh token %s has expired", token_fingerprint(refresh_token))
            await self.delete_refresh_token(refresh_token)
            return None

        return token_data.copy()

    async def delete_refresh_token(self, refresh_token: str) -> None:
        """Delete a refresh token from memory.

        Args:
            refresh_token: The refresh token string to delete
        """
        if not self._initialized:
            raise RuntimeError("Token storage not initialized. Call initialize() first.")

        if refresh_token in self._refresh_tokens:
            del self._refresh_tokens[refresh_token]
            logger.debug("Deleted refresh token %s", token_fingerprint(refresh_token))

    async def cleanup_expired_refresh_tokens(self) -> int:
        """Remove all expired refresh tokens from memory.

        Returns:
            Number of tokens removed
        """
        if not self._initialized:
            raise RuntimeError("Token storage not initialized. Call initialize() first.")

        now = int(time.time())
        expired_tokens = [
            token for token, data in self._refresh_tokens.items() if data["expires_at"] < now
        ]

        for token in expired_tokens:
            del self._refresh_tokens[token]

        count = len(expired_tokens)
        if count > 0:
            logger.info("Cleaned up %s expired refresh tokens", count)
        return count
