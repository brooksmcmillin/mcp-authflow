"""MCP Auth Framework - Reusable OAuth Authorization Server components.

Provides building blocks for OAuth 2.0 authorization servers that protect
MCP (Model Context Protocol) tool access:

- **Token storage** — Pluggable backends (in-memory, PostgreSQL) for access
  and refresh tokens.
- **CORS** — Origin validation helpers for OAuth/MCP endpoints.
- **Rate limiting** — Sliding-window rate limiter for token endpoints.
- **Responses** — Standardized OAuth 2.0 error responses (RFC 6749).
- **Validation** — Input sanitization for OAuth identifiers and scopes.
"""

from mcp_authflow.cors import build_cors_headers, get_cors_origin, parse_allowed_origins
from mcp_authflow.rate_limiting import AsyncRedisClient, SlidingWindowRateLimiter
from mcp_authflow.responses import (
    OAUTH_NO_CACHE_HEADERS,
    backend_connection_error,
    backend_invalid_response,
    backend_oauth_error,
    backend_timeout,
    invalid_client,
    invalid_grant,
    invalid_request,
    invalid_scope,
    oauth_error,
    rate_limit_exceeded,
    server_error,
    slow_down,
)
from mcp_authflow.storage import MemoryTokenStorage, TokenStorage
from mcp_authflow.validation import (
    VALID_ID_PATTERN,
    parse_json_field,
    parse_scope_field,
    validate_client_id,
)

__all__ = [
    # Version
    "__version__",
    # CORS
    "build_cors_headers",
    "get_cors_origin",
    "parse_allowed_origins",
    # Rate limiting
    "AsyncRedisClient",
    "SlidingWindowRateLimiter",
    # OAuth responses
    "OAUTH_NO_CACHE_HEADERS",
    "backend_connection_error",
    "backend_invalid_response",
    "backend_oauth_error",
    "backend_timeout",
    "invalid_client",
    "invalid_grant",
    "invalid_request",
    "invalid_scope",
    "oauth_error",
    "rate_limit_exceeded",
    "server_error",
    "slow_down",
    # Storage
    "MemoryTokenStorage",
    "PostgresTokenStorage",
    "TokenStorage",
    # Validation
    "VALID_ID_PATTERN",
    "parse_json_field",
    "parse_scope_field",
    "validate_client_id",
]

__version__ = "0.3.0"


def __getattr__(name: str) -> type:
    if name == "PostgresTokenStorage":
        from mcp_authflow.storage.postgres import PostgresTokenStorage  # noqa: PLC0415

        return PostgresTokenStorage
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
