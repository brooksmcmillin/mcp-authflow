"""MCP Auth Framework - Reusable OAuth Authorization Server components.

Provides building blocks for OAuth 2.0 authorization servers that protect
MCP (Model Context Protocol) tool access:

- **Token storage** — Pluggable backends (in-memory, PostgreSQL) for access
  and refresh tokens.
- **CORS** — Origin validation helpers for OAuth/MCP endpoints.
- **Rate limiting** — Sliding-window rate limiter for token endpoints.
- **Registration** — RFC 7591 Dynamic Client Registration handler factory
  with a pluggable :class:`ClientRegistry` persistence interface.
- **Responses** — Standardized OAuth 2.0 error responses (RFC 6749).
- **Validation** — Input sanitization for OAuth identifiers and scopes.
- **Client authentication** — ``private_key_jwt`` (RFC 7523) verification
  with an algorithm allowlist and replay protection.
- **PKCE** — ``code_verifier`` / ``code_challenge`` verification and
  validation (RFC 7636) for the token endpoint.
"""

from mcp_authflow.client_auth import (
    ALLOWED_JWT_ALGORITHMS,
    BLOCKED_JWT_ALGORITHMS,
    JWT_CLIENT_ASSERTION_TYPE,
    JWKSProvider,
    JWTAuthError,
    JWTClientAuthenticator,
)
from mcp_authflow.cors import build_cors_headers, get_cors_origin, parse_allowed_origins
from mcp_authflow.pkce import (
    ALLOWED_CODE_CHALLENGE_METHODS,
    validate_code_challenge,
    validate_code_challenge_method,
    validate_code_verifier,
    verify_pkce,
)
from mcp_authflow.rate_limiting import AsyncRedisClient, SlidingWindowRateLimiter
from mcp_authflow.registration import (
    ClientRegistrationRequest,
    ClientRegistry,
    MemoryClientRegistry,
    RegisteredClient,
    build_register_handler,
)
from mcp_authflow.responses import (
    OAUTH_NO_CACHE_HEADERS,
    access_denied,
    authorization_pending,
    backend_connection_error,
    backend_invalid_response,
    backend_oauth_error,
    backend_timeout,
    expired_token,
    invalid_client,
    invalid_grant,
    invalid_redirect_uri,
    invalid_request,
    invalid_scope,
    oauth_error,
    pkce_required,
    rate_limit_exceeded,
    server_error,
    slow_down,
    unsupported_grant_type,
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
    # Client authentication (RFC 7523 private_key_jwt)
    "ALLOWED_JWT_ALGORITHMS",
    "BLOCKED_JWT_ALGORITHMS",
    "JWT_CLIENT_ASSERTION_TYPE",
    "JWKSProvider",
    "JWTAuthError",
    "JWTClientAuthenticator",
    # Dynamic Client Registration (RFC 7591)
    "ClientRegistrationRequest",
    "ClientRegistry",
    "MemoryClientRegistry",
    "RegisteredClient",
    "build_register_handler",
    # OAuth responses
    "OAUTH_NO_CACHE_HEADERS",
    "access_denied",
    "authorization_pending",
    "backend_connection_error",
    "backend_invalid_response",
    "backend_oauth_error",
    "backend_timeout",
    "expired_token",
    "invalid_client",
    "invalid_grant",
    "invalid_redirect_uri",
    "invalid_request",
    "invalid_scope",
    "oauth_error",
    "pkce_required",
    "rate_limit_exceeded",
    "server_error",
    "slow_down",
    "unsupported_grant_type",
    # Storage
    "MemoryTokenStorage",
    "PostgresTokenStorage",
    "TokenStorage",
    # Validation
    "VALID_ID_PATTERN",
    "parse_json_field",
    "parse_scope_field",
    "validate_client_id",
    # PKCE (RFC 7636)
    "ALLOWED_CODE_CHALLENGE_METHODS",
    "validate_code_challenge",
    "validate_code_challenge_method",
    "validate_code_verifier",
    "verify_pkce",
]

__version__ = "0.6.0"


def __getattr__(name: str) -> type:
    if name == "PostgresTokenStorage":
        from mcp_authflow.storage.postgres import PostgresTokenStorage  # noqa: PLC0415

        return PostgresTokenStorage
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
