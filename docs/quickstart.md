# Quickstart

A minimal authorization server: one `/token` endpoint that issues access tokens, one `/introspect` endpoint that resource servers query to validate them. The complete file is about 50 lines and is enough to authenticate an MCP client end-to-end over RFC 7662.

## Install

```bash
pip install mcp-authflow
```

For production, also install the PostgreSQL extra so tokens survive restarts:

```bash
pip install mcp-authflow[postgres]
```

## A minimal authorization server

```python title="auth_server.py"
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

storage = MemoryTokenStorage()
limiter = SlidingWindowRateLimiter(requests_per_window=60, window_seconds=3600)


async def token_endpoint(request: Request) -> JSONResponse:
    form = await request.form()
    client_id = str(form.get("client_id", ""))

    if not await limiter.is_allowed(client_id):
        return rate_limit_exceeded(
            "Too many requests",
            retry_after=await limiter.get_retry_after(client_id),
        )

    if not validate_client_id(client_id):
        return invalid_request("Invalid client_id format")

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

Save the file as `auth_server.py` and start it with uvicorn on port 8000:

```bash
uvicorn auth_server:app --port 8000
```

## Try it

```bash
# Mint a token
curl -s -X POST http://localhost:8000/token \
  -d "client_id=demo-client&scope=read" | jq

# Inspect it (this is what a resource server would do)
curl -s -X POST http://localhost:8000/introspect \
  -d "token=<paste-token-here>" | jq
```

## Swap to PostgreSQL

For production, replace [`MemoryTokenStorage`][mcp_authflow.storage.MemoryTokenStorage] with [`PostgresTokenStorage`][mcp_authflow.storage.PostgresTokenStorage]:

```python
from mcp_authflow.storage import PostgresTokenStorage

storage = PostgresTokenStorage(database_url="postgresql://user:pass@host/db")
# Or read DATABASE_URL from the environment
storage = PostgresTokenStorage()
```

The interface is identical, but `PostgresTokenStorage` does **not** create its schema — `await storage.initialize()` only opens the connection pool. Create the tables yourself before first use (see the [DDL in the README](https://github.com/brooksmcmillin/mcp-authflow#token-storage)).

## Next steps

- [Architecture](architecture.md): the full client → auth server → resource server flow.
- [API Reference](api/index.md): module-by-module reference.
- [mcp-authflow-resource](https://github.com/brooksmcmillin/mcp-authflow-resource): the matching resource server.
