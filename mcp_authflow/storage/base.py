"""Abstract base class for token storage implementations."""

import hashlib
from abc import ABC, abstractmethod
from typing import Any, TypeAlias

UserId: TypeAlias = int | str
"""Identifier of the user who authorized a token.

Deliberately not narrowed to ``int``: consuming applications key users on
anything from a ``SERIAL``/``BIGINT`` counter to a ``UUID`` or an external
subject string. Storage backends pass the value straight through, so the type
you hand in has to match the ``user_id`` column type in your DDL (see the README
"Choosing a ``user_id`` column type" section for the ``BIGINT``/``UUID``/``TEXT``
variants). Pass UUIDs in their string form.
"""


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


def hash_token(token: str) -> str:
    """Return the non-reversible digest used to store and look up a token.

    Storage backends key tokens on this digest rather than the raw secret so a
    database compromise (backup leak, read replica, or SQLi in a consuming app)
    does not yield directly replayable credentials (CWE-312 / CWE-522). Tokens
    are high-entropy, so an unsalted SHA-256 is sufficient and keeps lookups a
    single indexed equality match.

    Args:
        token: The secret token to digest.

    Returns:
        The SHA-256 hex digest of the token.
    """
    return hashlib.sha256(token.encode()).hexdigest()


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
        user_id: UserId | None = None,
    ) -> None:
        """Store an access token.

        Args:
            token: The access token string
            client_id: OAuth client ID
            scopes: List of granted scopes
            expires_at: Unix timestamp when token expires
            resource: Optional RFC 8707 resource binding
            user_id: Optional ID of the user who authorized the token. May be an
                int or a str so it can match the consumer's user primary key
                (see :data:`~mcp_authflow.storage.base.UserId`)
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
        user_id: UserId | None = None,
    ) -> None:
        """Store a refresh token.

        Args:
            refresh_token: The refresh token string
            client_id: OAuth client ID
            scopes: List of granted scopes
            expires_at: Unix timestamp when token expires
            resource: Optional RFC 8707 resource binding
            user_id: Optional ID of the user who authorized the token. May be an
                int or a str so it can match the consumer's user primary key
                (see :data:`~mcp_authflow.storage.base.UserId`)
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

    @abstractmethod
    async def get_refresh_token_count(self) -> int:
        """Get the total number of refresh tokens in storage.

        Returns:
            Number of refresh tokens stored
        """
        ...
