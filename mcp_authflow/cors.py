"""CORS origin validation for MCP OAuth endpoints."""

import os

from starlette.requests import Request


def parse_allowed_origins(env_var: str = "ALLOWED_MCP_ORIGINS") -> list[str]:
    """Parse allowed CORS origins from a comma-separated environment variable.

    Args:
        env_var: Name of the environment variable to read.

    Returns:
        List of allowed origin strings, stripped of whitespace.
    """
    raw = os.getenv(env_var, "")
    if not raw:
        return []
    return [origin.strip() for origin in raw.split(",") if origin.strip()]


def get_cors_origin(request: Request, allowed_origins: list[str]) -> str:
    """Get CORS origin header value based on request origin.

    Only returns the origin if it's in the allowed list, otherwise returns
    empty string to deny CORS access.

    Args:
        request: The incoming request.
        allowed_origins: List of allowed origin strings.

    Returns:
        Origin value for Access-Control-Allow-Origin header.
    """
    request_origin = request.headers.get("origin", "")
    if request_origin in allowed_origins:
        return request_origin
    return ""


def build_cors_headers(request: Request, allowed_origins: list[str]) -> dict[str, str]:
    """Build standard CORS headers for OAuth discovery endpoints.

    Only includes Access-Control-Allow-Origin when the request origin is
    in the allowlist. Omits it entirely for disallowed origins per the
    CORS specification.

    Args:
        request: The incoming request.
        allowed_origins: List of allowed origin strings.

    Returns:
        Dict of CORS headers.
    """
    headers: dict[str, str] = {
        "Access-Control-Allow-Methods": "GET, OPTIONS",
        "Access-Control-Allow-Headers": "Authorization, Content-Type, Accept",
        # Access-Control-Allow-Origin is derived from the request Origin, so
        # caches must key on Origin to avoid serving a permissive ACAO header
        # generated for a trusted origin to a different, untrusted one
        # (Fetch spec requirement).
        "Vary": "Origin",
    }
    origin = get_cors_origin(request, allowed_origins)
    if origin:
        headers["Access-Control-Allow-Origin"] = origin
    return headers
