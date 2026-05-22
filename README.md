# mcp-authflow

OAuth 2.0 Authorization Server framework for [MCP](https://modelcontextprotocol.io/) servers. Issue and manage tokens that protect MCP tool access.

Pair with [mcp-authflow-resource](https://github.com/brooksmcmillin/mcp-authflow-resource) on the resource server side.

## Features

- **Token storage** with PostgreSQL and in-memory backends
- **RFC 6749** standardized OAuth error responses
- **RFC 7523 `private_key_jwt`** client authentication with algorithm allowlist and JTI replay protection (Redis or in-memory)
- **RFC 7636 PKCE** verification (`S256` + `plain`) and input validation for the token endpoint
- **Sliding-window rate limiting** for token endpoints
- **Input validation** for client IDs and scopes
- **CORS helpers** with origin allowlisting
- **Async-first** design, built on Starlette

## Installation

```bash
pip install mcp-authflow

# With PostgreSQL token storage (production)
pip install mcp-authflow[postgres]
```

## Quick Start

Build an OAuth authorization server that issues tokens for MCP clients:

```python
import secrets
import time
from contextlib import asynccontextmanager

from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route

from mcp_authflow.rate_limiting import SlidingWindowRateLimiter
from mcp_authflow.responses import invalid_request, rate_limit_exceeded
from mcp_authflow.storage import MemoryTokenStorage
from mcp_authflow.validation import parse_scope_field, validate_client_id

# --- Setup ---

storage = MemoryTokenStorage()  # Use PostgresTokenStorage for production
limiter = SlidingWindowRateLimiter(requests_per_window=60, window_seconds=3600)


# --- Token endpoint ---

async def token_endpoint(request: Request) -> JSONResponse:
    form = await request.form()
    client_id = str(form.get("client_id", ""))

    # Rate limit per client
    if not limiter.is_allowed(client_id):
        return rate_limit_exceeded(
            "Too many requests",
            retry_after=limiter.get_retry_after(client_id),
        )

    # Validate client
    if not validate_client_id(client_id):
        return invalid_request("Invalid client_id format")

    # Issue token
    token = secrets.token_urlsafe(32)
    scopes = parse_scope_field(form.get("scope"))
    expires_at = int(time.time()) + 3600

    await storage.store_token(
        token=token,
        client_id=client_id,
        scopes=scopes.split(),
        expires_at=expires_at,
        resource=str(form.get("resource", "")),
    )

    return JSONResponse({
        "access_token": token,
        "token_type": "bearer",
        "expires_in": 3600,
        "scope": scopes,
    })


# --- Introspection endpoint (called by resource servers) ---

async def introspect_endpoint(request: Request) -> JSONResponse:
    form = await request.form()
    token = str(form.get("token", ""))

    token_data = await storage.load_token(token)
    if not token_data or token_data["expires_at"] < time.time():
        return JSONResponse({"active": False})

    return JSONResponse({
        "active": True,
        "client_id": token_data["client_id"],
        "scope": " ".join(token_data["scopes"]),
        "exp": token_data["expires_at"],
        "aud": token_data.get("resource", ""),
    })


@asynccontextmanager
async def lifespan(app):
    await storage.initialize()
    yield
    await storage.close()


app = Starlette(
    routes=[
        Route("/token", token_endpoint, methods=["POST"]),
        Route("/introspect", introspect_endpoint, methods=["POST"]),
    ],
    lifespan=lifespan,
)
```

Run with: `uvicorn myapp:app --port 8000`

## Architecture

```
                         MCP Client (Claude, etc.)
                                |
                  1. Authorization request
                                |
                                v
                    +---------------------+
                    |   Auth Server        |   <-- this package
                    |   (mcp-authflow)  |
                    |                     |
                    |  /token             |   2. Issues access token
                    |  /introspect        |   4. Validates token
                    +---------------------+
                                ^
                                |
                     4. Token introspection (RFC 7662)
                                |
                    +---------------------+
                    |   Resource Server    |   <-- mcp-authflow-resource
                    |   (MCP tools)       |
                    |                     |
                    |  3. Client calls    |
                    |     MCP tools with  |
                    |     Bearer token    |
                    +---------------------+
```

1. MCP client authenticates with the auth server
2. Auth server issues an access token (stored in PostgreSQL or memory)
3. Client calls MCP tools on the resource server with the Bearer token
4. Resource server validates the token by calling the auth server's `/introspect` endpoint

## API Reference

### Token Storage

Abstract base class with two implementations:

```python
from mcp_authflow.storage import MemoryTokenStorage, PostgresTokenStorage

# In-memory (development/testing)
storage = MemoryTokenStorage()

# PostgreSQL (production) -- requires `postgres` extra
storage = PostgresTokenStorage(database_url="postgresql://user:pass@host/db")
# Or reads DATABASE_URL env var if no argument provided
storage = PostgresTokenStorage()

await storage.initialize()  # Create tables / prepare connections
```

**Storage interface:**

| Method | Description |
|--------|-------------|
| `store_token(token, client_id, scopes, expires_at, resource?, user_id?)` | Store an access token |
| `load_token(token) -> dict \| None` | Look up a token |
| `delete_token(token)` | Revoke a token |
| `cleanup_expired_tokens() -> int` | Purge expired tokens, returns count |
| `get_token_count() -> int` | Count active tokens |
| `store_refresh_token(...)` | Store a refresh token (same interface) |
| `load_refresh_token(token) -> dict \| None` | Look up a refresh token |
| `delete_refresh_token(token)` | Revoke a refresh token |
| `cleanup_expired_refresh_tokens() -> int` | Purge expired refresh tokens, returns count |

Token data returned by `load_token()`:

```python
{
    "token": str,
    "client_id": str,
    "scopes": list[str],
    "resource": str | None,       # RFC 8707 resource binding
    "expires_at": int,            # Unix timestamp
    "created_at": int,            # Unix timestamp
    "user_id": int | None,
}
```

### OAuth Error Responses

Standardized error helpers following RFC 6749:

```python
from mcp_authflow.responses import (
    invalid_request,       # 400 - Missing/invalid parameters
    invalid_client,        # 401 - Authentication failure
    invalid_grant,         # 400 - Expired/invalid code or token
    invalid_scope,         # 400 - Scope violation
    slow_down,             # 400 - Device flow rate limiting
    rate_limit_exceeded,   # 429 - Too many requests
    server_error,          # 500 - Internal error
    backend_timeout,       # 504 - Upstream timeout
)
```

Each returns a Starlette `JSONResponse` with the appropriate status code and `Cache-Control: no-store` header.

### Rate Limiting

```python
from mcp_authflow.rate_limiting import SlidingWindowRateLimiter

limiter = SlidingWindowRateLimiter(
    requests_per_window=60,   # Max requests per window
    window_seconds=3600,      # Window duration (1 hour)
)

if not limiter.is_allowed(client_id):
    retry_after = limiter.get_retry_after(client_id)  # Seconds until next allowed request
```

### Input Validation

```python
from mcp_authflow.validation import validate_client_id, parse_scope_field

validate_client_id("my-client-123")  # True (alphanumeric + hyphens/underscores)
validate_client_id("")               # False

parse_scope_field("read write")      # "read write"
parse_scope_field(["read", "write"]) # "read write"
parse_scope_field(None)              # "read" (default)
```

### CORS

```python
from mcp_authflow.cors import parse_allowed_origins, build_cors_headers

# Reads ALLOWED_MCP_ORIGINS env var (comma-separated)
origins = parse_allowed_origins()

# Returns CORS headers if request origin is in allowlist
headers = build_cors_headers(request, origins)
```

## Configuration

| Env Variable | Description | Default |
|-------------|-------------|---------|
| `DATABASE_URL` | PostgreSQL connection string (for `PostgresTokenStorage`) | Required for postgres |
| `ALLOWED_MCP_ORIGINS` | Comma-separated allowed CORS origins | Empty (no CORS) |

## License

MIT
