"""Abstract base class for token storage implementations."""

import hashlib
from abc import ABC, abstractmethod
from typing import Any


def token_fingerprint(token: str) -> str:
    """Return a short, non-reversible fingerprint of a token for logging.

    Logging a raw token prefix leaks a large fraction of its entropy into log
    storage. A truncated SHA-256 digest lets operators correlate log lines for
    the same token without exposing material that shrinks an offline search
    space.

    Args:
        token: The secret token (or client_id) to fingerprint.

    Returns:
        A ``"fp:"``-prefixed 8-character hex digest.
    """
    return "fp:" + hashlib.sha256(token.encode()).hexdigest()[:8]


class TokenStorage(ABC):
    """Abstract interface for MCP token storage."""

    @abstractmethod
    async def initialize(self) -> None:
        """Initialize the storage backend."""
        ...

    @abstractmethod
    async def close(self) -> None:
        """Close the storage backend and clean up resources."""
        ...

    @abstractmethod
    async def store_token(
        self,
        token: str,
        client_id: str,
        scopes: list[str],
        expires_at: int,
        resource: str | None = None,
        user_id: int | None = None,
    ) -> None:
        """Store an access token.

        Args:
            token: The access token string
            client_id: OAuth client ID
            scopes: List of granted scopes
            expires_at: Unix timestamp when token expires
            resource: Optional RFC 8707 resource binding
            user_id: Optional ID of the user who authorized the token
        """
        ...

    @abstractmethod
    async def load_token(self, token: str) -> dict[str, Any] | None:
        """Load an access token.

        Args:
            token: The access token string to look up

        Returns:
            Token data dict if found and not expired, None otherwise
        """
        ...

    @abstractmethod
    async def delete_token(self, token: str) -> None:
        """Delete a token.

        Args:
            token: The access token string to delete
        """
        ...

    @abstractmethod
    async def store_refresh_token(
        self,
        refresh_token: str,
        client_id: str,
        scopes: list[str],
        expires_at: int,
        resource: str | None = None,
        user_id: int | None = None,
    ) -> None:
        """Store a refresh token.

        Args:
            refresh_token: The refresh token string
            client_id: OAuth client ID
            scopes: List of granted scopes
            expires_at: Unix timestamp when token expires
            resource: Optional RFC 8707 resource binding
            user_id: Optional ID of the user who authorized the token
        """
        ...

    @abstractmethod
    async def load_refresh_token(self, refresh_token: str) -> dict[str, Any] | None:
        """Load a refresh token.

        Args:
            refresh_token: The refresh token string to look up

        Returns:
            Token data dict if found and not expired, None otherwise
        """
        ...

    @abstractmethod
    async def delete_refresh_token(self, refresh_token: str) -> None:
        """Delete a refresh token.

        Args:
            refresh_token: The refresh token string to delete
        """
        ...

    @abstractmethod
    async def cleanup_expired_tokens(self) -> int:
        """Remove all expired access tokens.

        Returns:
            Number of tokens removed
        """
        ...

    @abstractmethod
    async def cleanup_expired_refresh_tokens(self) -> int:
        """Remove all expired refresh tokens.

        Returns:
            Number of tokens removed
        """
        ...

    @abstractmethod
    async def get_token_count(self) -> int:
        """Get the total number of access tokens in storage.

        Returns:
            Number of tokens stored
        """
        ...
