"""Client authentication primitives for OAuth 2.0 token endpoints.

Currently provides ``private_key_jwt`` (RFC 7523) verification. The package
exposes the high-level :class:`JWTClientAuthenticator`, the
:class:`JWKSProvider` integration point, and the algorithm allowlist /
blocklist constants for callers that need them.
"""

from mcp_authflow.client_auth.jwt import (
    ALLOWED_JWT_ALGORITHMS,
    BLOCKED_JWT_ALGORITHMS,
    JWT_CLIENT_ASSERTION_TYPE,
    JWT_MAX_CLOCK_SKEW_SECONDS,
    JWT_MAX_LIFETIME_SECONDS,
    AsyncRedisClient,
    JWKSProvider,
    JWTAuthError,
    JWTClientAuthenticator,
)

__all__ = [
    "ALLOWED_JWT_ALGORITHMS",
    "BLOCKED_JWT_ALGORITHMS",
    "JWT_CLIENT_ASSERTION_TYPE",
    "JWT_MAX_CLOCK_SKEW_SECONDS",
    "JWT_MAX_LIFETIME_SECONDS",
    "AsyncRedisClient",
    "JWKSProvider",
    "JWTAuthError",
    "JWTClientAuthenticator",
]
