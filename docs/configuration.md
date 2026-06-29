# Configuration

## Environment variables

| Variable | Used by | Description | Default |
|---|---|---|---|
| `DATABASE_URL` | [`PostgresTokenStorage`][mcp_authflow.storage.PostgresTokenStorage] | PostgreSQL connection string (read when no `database_url` argument is passed). | (required) |
| `ALLOWED_MCP_ORIGINS` | [`parse_allowed_origins`][mcp_authflow.cors.parse_allowed_origins] | Comma-separated list of CORS-allowed origins. | empty (no CORS) |

## Storage backends

Two backends ship with the package.

=== "In-memory (dev)"

    ```python
    from mcp_authflow.storage import MemoryTokenStorage

    storage = MemoryTokenStorage()
    await storage.initialize()
    ```

    Token state lives in a dict. Cleared on restart. Use this for tests and local development only.

=== "PostgreSQL (prod)"

    ```python
    from mcp_authflow.storage import PostgresTokenStorage

    # Explicit URL
    storage = PostgresTokenStorage(database_url="postgresql://user:pass@host/db")

    # Or read DATABASE_URL from env
    storage = PostgresTokenStorage()

    await storage.initialize()  # Opens the connection pool (does NOT create tables)
    ```

    Requires the `postgres` extra: `pip install mcp-authflow[postgres]`.

    `PostgresTokenStorage` does **not** create or migrate its schema — apply the
    table DDL yourself before first use. See
    [the README](https://github.com/brooksmcmillin/mcp-authflow#token-storage)
    for the full schema.

To plug in a different backend, implement the [`TokenStorage`][mcp_authflow.storage.TokenStorage] abstract base.

## Rate limiting backend

[`SlidingWindowRateLimiter`][mcp_authflow.rate_limiting.SlidingWindowRateLimiter] runs in-process by default. For multi-replica deployments, pass an async Redis client:

```python
from redis.asyncio import Redis

from mcp_authflow.rate_limiting import SlidingWindowRateLimiter

limiter = SlidingWindowRateLimiter(
    requests_per_window=60,
    window_seconds=3600,
    redis=Redis.from_url("redis://localhost:6379"),
)
```

Any object that satisfies [`AsyncRedisClient`][mcp_authflow.rate_limiting.AsyncRedisClient] will work. The protocol covers only the methods this module actually calls.

## CORS

```python
from mcp_authflow.cors import build_cors_headers, parse_allowed_origins

origins = parse_allowed_origins()  # reads ALLOWED_MCP_ORIGINS

# In a request handler
headers = build_cors_headers(request, origins)
```

Each helper is a single function. Wire them into middleware or attach per-route as you see fit.
