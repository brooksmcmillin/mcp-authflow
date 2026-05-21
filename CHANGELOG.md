# Changelog

## 0.5.0

### New: RFC 7523 `private_key_jwt` client authentication

Adds `mcp_authflow.client_auth` — verifies `client_assertion` JWTs at the
token endpoint per RFC 7523 (JWT Profile for OAuth 2.0 Client
Authentication).

```python
from mcp_authflow import JWTClientAuthenticator, JWTAuthError

class MyJWKSProvider:
    async def get_jwks(self, client_id: str) -> dict | None:
        # look up the client's JWKS however you like
        ...

authenticator = JWTClientAuthenticator(
    token_endpoint="https://auth.example.com/token",
    jwks_provider=MyJWKSProvider(),
    # optionally: redis=redis.asyncio.Redis(...) for a shared replay cache
)

try:
    await authenticator.authenticate(
        client_id=client_id,
        client_assertion=form["client_assertion"],
        client_assertion_type=form["client_assertion_type"],
    )
except JWTAuthError as e:
    return invalid_client(str(e))
```

Security properties:

- **Algorithm allowlist** — only asymmetric algorithms (`RS{256,384,512}`,
  `ES{256,384,512}`, `PS{256,384,512}`) are accepted. `none` and HMAC
  algorithms are explicitly blocked to prevent algorithm-confusion attacks.
- **Replay protection** — `jti` is required and tracked. Provide a Redis
  client (`redis.asyncio.Redis`) for a persistent, multi-process-safe cache
  (`SET NX PX`); otherwise an in-memory cache with TTL cleanup is used.
- **Lifetime ceiling** — assertions with `iat` more than five minutes in the
  past are rejected even if their `exp` would still accept them.
- **Required claims** — `iss`, `sub`, `aud`, `exp`, `iat`, and `jti` are all
  required; `sub == client_id` is enforced per RFC 7523.

The new `JWKSProvider` Protocol keeps key-material resolution out of the
library. Plug in static JWKS, RFC 7591 DCR records, Client ID Metadata
Documents, or any other source by implementing
`async def get_jwks(client_id: str) -> dict | None`.

Adds `pyjwt[crypto] >= 2.8.0` to runtime dependencies.

## 0.4.0

### New: RFC 7591 Dynamic Client Registration

Adds `mcp_authflow.registration` — a storage-agnostic handler factory and
persistence interface for RFC 7591 Dynamic Client Registration.

```python
from mcp_authflow.registration import (
    MemoryClientRegistry,
    build_register_handler,
)
from starlette.routing import Route

handler = build_register_handler(
    MemoryClientRegistry(),
    default_scope="mcp:tools",
)
routes = [Route("/register", handler, methods=["POST"])]
```

Components:

- `ClientRegistry` — abstract persistence interface (`create_client`,
  `get_client`) that consumers implement against their own backend
  (database, upstream IdP, etc.).
- `MemoryClientRegistry` — process-local reference implementation.
- `ClientRegistrationRequest` / `RegisteredClient` — parsed-input and
  issued-client dataclasses.
- `build_register_handler(...)` — returns a Starlette endpoint. Optional
  hooks let the caller plug in an `mcp_authflow` rate limiter, default
  redirect URIs, redirect-URI rewriters, a client-name factory, and
  post-register hooks (e.g. cache warming) without forking the handler.

The handler maps `grant_types=["client_credentials"]` to a confidential
client (`token_endpoint_auth_method=client_secret_post`); any other
request becomes a public client (`token_endpoint_auth_method=none`) with
the MCP/auth-code/refresh/device-code bundle.

## 0.3.0

### Breaking changes

- `SlidingWindowRateLimiter.is_allowed()` and `get_retry_after()` are now
  coroutines. Callers must `await` them:

  ```python
  # Before
  if limiter.is_allowed(client_id):
      ...

  # After
  if await limiter.is_allowed(client_id):
      ...
  ```

  This is required so the limiter can optionally back its sliding window
  with Redis. The change applies to both the in-memory and Redis paths.

### Added

- `SlidingWindowRateLimiter` accepts an optional `redis: AsyncRedisClient`
  argument. When provided, request timestamps are stored in a Redis sorted
  set under the key `mcp_auth:ratelimit:<client_id>:<window_seconds>`,
  giving shared state across replicas and survival across pod restarts.
  When omitted, the limiter falls back to the existing in-process
  `defaultdict` (suitable for local development and single-replica
  deployments).
- New `AsyncRedisClient` Protocol describes the subset of the
  `redis.asyncio.Redis` interface the limiter needs (`zadd`,
  `zremrangebyscore`, `zcard`, `expire`, `zrange`). Pass any object that
  satisfies the protocol — no hard dependency on `redis-py` is added.

## 0.2.0

### Breaking changes

- Renamed Python import from `mcp_auth_framework` to `mcp_authflow` so it
  matches the PyPI distribution name. The package is now installed and
  imported under the same name:

  ```python
  # Before
  from mcp_auth_framework import MemoryTokenStorage

  # After
  from mcp_authflow import MemoryTokenStorage
  ```

  No compatibility shim is provided; update imports directly.
- The GitHub repository moved from `brooksmcmillin/mcpauth` to
  `brooksmcmillin/mcp-authflow`. GitHub redirects the old URLs, but
  bookmarks and CI configurations should be updated.

## 0.1.0

Initial release on PyPI as `mcp-authflow` (imported as `mcp_auth_framework`).
OAuth 2.0 Authorization Server primitives for MCP: token storage
(in-memory + PostgreSQL), RFC 6749 error helpers, sliding-window rate
limiter, input validation, and CORS helpers.
