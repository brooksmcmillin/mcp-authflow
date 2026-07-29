# mcp-authflow

OAuth 2.0 Authorization Server framework for [MCP](https://modelcontextprotocol.io/) servers. Issue and manage tokens that protect MCP tool access.

Pair with [mcp-authflow-resource](https://github.com/brooksmcmillin/mcp-authflow-resource) on the resource server side.

## Features

- **Token storage** with PostgreSQL and in-memory backends
- **RFC 6749** standardized OAuth error responses
- **RFC 7523 `private_key_jwt`** client authentication with algorithm allowlist and JTI replay protection (Redis or in-memory)
- **RFC 7636 PKCE** verification (`S256` + `plain`, with an opt-in S256-only policy) and input validation for the token endpoint
- **RFC 8628 Device Authorization Grant** — sans-IO polling state machine and code generators
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
    if not await limiter.is_allowed(client_id):
        return rate_limit_exceeded(
            "Too many requests",
            retry_after=await limiter.get_retry_after(client_id),
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

await storage.initialize()  # Open the connection pool (in-memory needs no setup)
```

`PostgresTokenStorage` does **not** create or migrate its schema — it expects
the tables to already exist, so you stay in control of migrations. Apply this
DDL (e.g. via your migration tool) before first use:

```sql
CREATE TABLE IF NOT EXISTS mcp_access_tokens (
    token       TEXT PRIMARY KEY,  -- SHA-256 digest of the access token, not the raw value
    client_id   TEXT NOT NULL,
    scopes      TEXT NOT NULL DEFAULT '',
    resource    TEXT,
    expires_at  TIMESTAMPTZ NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    user_id     INTEGER            -- match your own user PK type; see below
);

-- Speeds up expiry checks on load and the `cleanup_expired_tokens` sweep
-- (`DELETE ... WHERE expires_at < now()`), which would otherwise seq-scan.
CREATE INDEX IF NOT EXISTS idx_mcp_access_tokens_expires_at
    ON mcp_access_tokens (expires_at);

-- Only needed if you use the refresh-token methods.
CREATE TABLE IF NOT EXISTS mcp_refresh_tokens (
    token       TEXT PRIMARY KEY,  -- SHA-256 digest of the refresh token, not the raw value
    client_id   TEXT NOT NULL,
    scopes      TEXT NOT NULL DEFAULT '',
    resource    TEXT,
    expires_at  TIMESTAMPTZ NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    user_id     INTEGER            -- match your own user PK type; see below
);

CREATE INDEX IF NOT EXISTS idx_mcp_refresh_tokens_expires_at
    ON mcp_refresh_tokens (expires_at);
```

On an already-large, live table, build the index with `CREATE INDEX
CONCURRENTLY` (run outside a transaction) so the migration does not take an
`ACCESS EXCLUSIVE` lock that blocks concurrent auth traffic:

```sql
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_mcp_access_tokens_expires_at
    ON mcp_access_tokens (expires_at);
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_mcp_refresh_tokens_expires_at
    ON mcp_refresh_tokens (expires_at);
```

#### Choosing a `user_id` column type

`INTEGER` above is only a default that suits a `SERIAL` user table. The library
never compares, casts, or joins on `user_id` — it stores whatever you pass and
returns it unchanged — so pick the type that matches your own user primary key
and use it in both token tables:

| Your user PK | `user_id` column | Value to pass |
|--------------|------------------|---------------|
| `SERIAL` / `INTEGER` | `INTEGER` | `int` |
| `BIGSERIAL` / `BIGINT` | `BIGINT` | `int` |
| `UUID` | `UUID` | `str` (canonical hex form) |
| External subject / any string | `TEXT` | `str` |

`TEXT` is the type-agnostic choice if you want the schema to outlive a change of
user-ID scheme. Accordingly, `store_token()` / `store_refresh_token()` accept
`user_id: int | str | None` (exported as `mcp_authflow.UserId`), and
`load_token()` returns it as stored. Passing a value whose type does not match
the column is a plain Postgres type error, so keep the two in sync.

`user_id` is deliberately **not** indexed: nothing in the library looks tokens up
by user. If your application adds such a lookup (for example "revoke all tokens
for this user"), add the index yourself so it does not seq-scan:

```sql
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_mcp_access_tokens_user_id
    ON mcp_access_tokens (user_id);
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_mcp_refresh_tokens_user_id
    ON mcp_refresh_tokens (user_id);
```

#### Schema versioning and upgrades

The DDL above uses `CREATE TABLE IF NOT EXISTS`, which is a no-op when the table
already exists. That is the right behaviour for a fresh install, but it means
re-running the DDL after upgrading the library **does not** add any columns a
newer release introduced — Postgres silently keeps your existing table as-is,
and no error is raised. If a later version then references a column your table
is missing, backend queries fail at runtime with `UndefinedColumnError`.

To stay ahead of this:

- **Every release documents the schema it expects.** No release has yet added,
  dropped, or renamed a column: every column shown above has been in the DDL
  since it was first published, so the current minimum *shape* is simply the
  base tables above. When a future release does change a column, this README
  and the [CHANGELOG](CHANGELOG.md) will call it out and ship a copy-paste
  `ALTER TABLE` recipe next to the base `CREATE`.
- **A column's shape and its contents are different things.** 0.8.0 changed
  what the `token` column *holds* (a SHA-256 digest rather than the raw token)
  without changing its type, so it needs no `ALTER TABLE` but is still a
  breaking upgrade — see "Upgrading to 0.8.0" below.
- **Apply the upgrade DDL, don't just re-run `CREATE`.** Upgrade blocks use
  `ADD COLUMN IF NOT EXISTS` so they are safe to run more than once and safe on
  a table that predates or already has the column. The template for such a
  block looks like:

  ```sql
  -- Upgrade to <version>: adds <column> to the token tables.
  ALTER TABLE mcp_access_tokens  ADD COLUMN IF NOT EXISTS <column> <type>;
  ALTER TABLE mcp_refresh_tokens ADD COLUMN IF NOT EXISTS <column> <type>;
  ```

  There are no such blocks yet — no release has changed a column's type or
  added one. This section is where they will appear when one does.

#### Upgrading to 0.8.0

No DDL change is required: 0.8.0 added no columns and changed no types. But it
did change what the `token` column contains, from the raw token to its SHA-256
digest, so **every row written by 0.7.0 or earlier is unreadable after the
upgrade**. Access tokens and refresh tokens alike will fail to load and clients
will have to obtain new ones — plan the upgrade as you would a token revocation.

Rows written before the upgrade are inert rather than harmful: they can never
match a lookup again, and the `cleanup_expired_tokens()` /
`cleanup_expired_refresh_tokens()` sweeps remove them once `expires_at` passes.
To clear them immediately instead of waiting out the TTL:

```sql
DELETE FROM mcp_access_tokens;
DELETE FROM mcp_refresh_tokens;
```

As a backstop against the *shape* half of the problem, `initialize()` performs a
lightweight `information_schema` check on the token tables that already exist
and raises [`SchemaDriftError`](#storage-errors) naming any required column that
is missing, so drift fails fast at startup instead of surfacing as a mid-request
`UndefinedColumnError`. Tables you have not created are left alone (the
`mcp_refresh_tokens` table is only needed if you use the refresh-token methods).

#### Storage errors

Storage failures come in two kinds, and servers usually want to treat them
differently. Misconfiguration — no `DATABASE_URL`, a drifted schema, a method
called before `initialize()` — is reported with a subclass of `StorageError`,
and retrying never fixes it. Everything else (an unreachable database, a dropped
connection, a saturated pool) surfaces as an `asyncpg` error or `OSError`, and
may well be transient.

| Exception | Raised when | Also a |
|---|---|---|
| `StorageError` | base class for all of the below | `Exception` |
| `StorageConfigError` | no database URL was given and `DATABASE_URL` is unset | `ValueError` |
| `SchemaDriftError` | an existing token table is missing a required column | `RuntimeError` |
| `StorageNotInitializedError` | a storage method was called before `initialize()` | `RuntimeError` |

Each subclasses the builtin that the same condition raised in earlier releases,
so existing `except RuntimeError` / `except ValueError` handlers keep working.

Prefer aborting startup on `StorageError`. If you configured a database, you
asked for tokens that outlive a restart and are visible to every replica;
falling back to in-memory storage instead means a token issued by one replica is
rejected by the next, which is harder to diagnose than a refused startup:

```python
storage = PostgresTokenStorage(database_url)
try:
    await storage.initialize()
except StorageError:
    logger.exception("Token storage is misconfigured; refusing to start")
    raise
except (asyncpg.PostgresError, OSError):
    logger.warning("Database unavailable at startup, will retry")
    raise
```

Tokens are hashed at rest: the `token` column holds the SHA-256 hex digest of
the token, never the raw secret, so a database compromise does not leak
replayable credentials. Hashing is internal — the `store_token` / `load_token`
API still takes and returns the raw token. If you are upgrading a deployment
that previously stored raw tokens, treat this as a breaking schema change: the
digest is 64 hex characters, so existing rows will no longer match on lookup.
Perform an expand-contract migration (rehash existing tokens, or expire and
reissue them) as part of the upgrade.

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
    "user_id": int | str | None,  # exactly what was passed to store_token()
}
```

### OAuth Error Responses

Standardized error helpers following RFC 6749 (and the device-flow /
registration extensions). Each returns a ready-to-send Starlette
`JSONResponse`:

```python
from mcp_authflow.responses import (
    oauth_error,               # helper the others build on (default 400)
    invalid_request,           # 400 - Missing/invalid parameters
    invalid_client,            # 401 - Authentication failure
    invalid_grant,             # 400 - Expired/invalid code or token
    invalid_scope,             # 400 - Scope violation
    unsupported_grant_type,    # 400 - Unsupported grant_type (RFC 6749 §5.2)
    access_denied,             # 400 - User/AS denied the request
    invalid_redirect_uri,      # 400 - Bad redirect_uri (RFC 7591 §3.2.2)
    authorization_pending,     # 400 - Device flow: keep polling (RFC 8628 §3.5)
    slow_down,                 # 400 or 429 - Device flow: poll slower
    expired_token,             # 400 - Device flow: device_code expired
    pkce_required,             # 400 - PKCE is required for this client
    rate_limit_exceeded,       # 429 - Too many requests
    server_error,              # 500 (or 502/504) - Internal error
    backend_timeout,           # 504 - Upstream timeout
    backend_connection_error,  # 502 - Upstream connection failure
    backend_invalid_response,  # 502 - Malformed upstream response
    backend_oauth_error,       # passthrough of an upstream OAuth error dict
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

if not await limiter.is_allowed(client_id):
    retry_after = await limiter.get_retry_after(client_id)  # Seconds until next allowed request
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
