"""
OAuth error response helpers for MCP Auth server.

This module provides standardized error response functions following
OAuth 2.0 error response format (RFC 6749).
"""

from starlette.responses import JSONResponse

# Standard headers for OAuth responses
OAUTH_NO_CACHE_HEADERS: dict[str, str] = {"Cache-Control": "no-store"}


def oauth_error(
    error: str,
    description: str,
    status_code: int = 400,
    extra_headers: dict[str, str] | None = None,
) -> JSONResponse:
    """Create a standard OAuth error response.

    Args:
        error: OAuth error code (e.g., "invalid_request", "server_error")
        description: Human-readable error description
        status_code: HTTP status code (default 400)
        extra_headers: Additional headers to include (e.g., Retry-After)

    Returns:
        JSONResponse with OAuth error format
    """
    headers = OAUTH_NO_CACHE_HEADERS.copy()
    if extra_headers:
        headers.update(extra_headers)

    return JSONResponse(
        {"error": error, "error_description": description},
        status_code=status_code,
        headers=headers,
    )


def invalid_request(description: str) -> JSONResponse:
    """Create an invalid_request error response (400).

    Use for: missing required parameters, invalid parameter format.
    """
    return oauth_error("invalid_request", description, 400)


def invalid_client(description: str) -> JSONResponse:
    """Create an invalid_client error response (401).

    Use for: client authentication failed, unknown client.
    """
    return oauth_error("invalid_client", description, 401)


def slow_down(description: str, retry_after: int | None = None) -> JSONResponse:
    """Create a slow_down error response (400 or 429).

    Use for: rate limiting during device flow polling.

    Args:
        description: Error description
        retry_after: Optional retry-after value in seconds
    """
    extra_headers = {"Retry-After": str(retry_after)} if retry_after else None
    return oauth_error("slow_down", description, 400, extra_headers)


def rate_limit_exceeded(description: str, retry_after: int | None = None) -> JSONResponse:
    """Create a rate limit exceeded error response (429).

    Use for: too many requests to a generic endpoint (registration,
    introspection, etc.).

    Emits the ``too_many_requests`` error code so it does not collide with the
    device-flow polling signal produced by :func:`slow_down`. RFC 8628 §3.5
    reserves ``slow_down`` specifically for device-flow token polling, so a
    generic 429 must use a distinct code to avoid pushing clients into
    device-flow backoff.

    Args:
        description: Error description
        retry_after: Optional retry-after value in seconds
    """
    extra_headers = {"Retry-After": str(retry_after)} if retry_after else None
    return oauth_error("too_many_requests", description, 429, extra_headers)


def server_error(description: str, status_code: int = 500) -> JSONResponse:
    """Create a server_error response.

    Use for: internal server errors, backend failures.

    Args:
        description: Error description
        status_code: HTTP status code (500, 502, 504, etc.)
    """
    return oauth_error("server_error", description, status_code)


def backend_timeout() -> JSONResponse:
    """Create a backend timeout error response (504)."""
    return server_error("Backend timeout", 504)


def backend_connection_error() -> JSONResponse:
    """Create a backend connection error response (502)."""
    return server_error("Backend connection error", 502)


def backend_invalid_response() -> JSONResponse:
    """Create an invalid backend response error (502)."""
    return server_error("Invalid response from backend", 502)


def invalid_grant(description: str) -> JSONResponse:
    """Create an invalid_grant error response (400).

    Use for: invalid or expired authorization codes, refresh tokens, or device codes.
    """
    return oauth_error("invalid_grant", description, 400)


def invalid_scope(description: str) -> JSONResponse:
    """Create an invalid_scope error response (400).

    Use for: requested scope is invalid, unknown, or exceeds what was granted.
    """
    return oauth_error("invalid_scope", description, 400)


def unsupported_grant_type(description: str) -> JSONResponse:
    """Create an unsupported_grant_type error response (400, RFC 6749 §5.2).

    Use for: token endpoint received a grant_type the AS does not support.
    """
    return oauth_error("unsupported_grant_type", description, 400)


def access_denied(description: str) -> JSONResponse:
    """Create an access_denied error response (400, RFC 6749 §4.1.2.1 / §5.2).

    Use for: resource owner or AS denied the request (e.g., user declined
    consent at the ``/authorize`` step, or device flow ``authorize_device``
    was called with action=deny).
    """
    return oauth_error("access_denied", description, 400)


def invalid_redirect_uri(description: str) -> JSONResponse:
    """Create an invalid_redirect_uri error response (400, RFC 7591 §3.2.2).

    Use for: registration or authorization request supplied a redirect_uri
    that is not allowed for the client.
    """
    return oauth_error("invalid_redirect_uri", description, 400)


def authorization_pending(description: str = "Authorization pending") -> JSONResponse:
    """Create an authorization_pending error response (400, RFC 8628 §3.5).

    Use for: device flow token polling while the user has not yet completed
    authorization. Clients should continue polling at the configured
    ``interval``.
    """
    return oauth_error("authorization_pending", description, 400)


def expired_token(description: str = "Device code has expired") -> JSONResponse:
    """Create an expired_token error response (400, RFC 8628 §3.5).

    Use for: device flow token polling after the ``device_code`` has expired.
    """
    return oauth_error("expired_token", description, 400)


def pkce_required(
    description: str = "PKCE is required for public clients",
) -> JSONResponse:
    """Create an invalid_request error indicating PKCE is required (400).

    Public clients (no client_secret) MUST use PKCE per OAuth 2.1 / RFC 9700.
    This returns the standard ``invalid_request`` OAuth error code with a
    description that calls out the missing PKCE binding.
    """
    return oauth_error("invalid_request", description, 400)


def backend_oauth_error(error_dict: dict[str, str], status_code: int) -> JSONResponse:
    """Create a JSONResponse from an already-formatted OAuth error dict.

    Use for: forwarding transformed backend errors that are already in
    {"error": "...", "error_description": "..."} format.

    Args:
        error_dict: Dict with "error" and "error_description" keys
        status_code: HTTP status code from the backend response

    Returns:
        JSONResponse with Cache-Control: no-store header
    """
    return JSONResponse(
        error_dict,
        status_code=status_code,
        headers=OAUTH_NO_CACHE_HEADERS.copy(),
    )
