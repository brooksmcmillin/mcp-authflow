# Changelog

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
