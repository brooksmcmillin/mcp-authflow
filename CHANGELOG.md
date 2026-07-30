# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Add entries under `## [Unreleased]` as PRs merge. At release time the
`[Unreleased]` heading is promoted to the new version number (see
[RELEASING.md](https://github.com/brooksmcmillin/mcp-authflow/blob/main/RELEASING.md)).

## [Unreleased]

### Added

### Changed

### Deprecated

### Removed

### Fixed

### Security

- `TokenStorage` now exposes `revoke_client_tokens(client_id)`, implemented by
  both built-in backends, so authorization servers can immediately invalidate
  every access and refresh token bound to a deleted dynamic client as
  recommended by RFC 7592 section 2.3. PostgreSQL performs both deletions in a
  single transaction (while still supporting access-token-only schemas), and
  tokens belonging to other clients are unaffected. This new abstract method
  is a breaking change for custom `TokenStorage` subclasses, which must
  implement it when upgrading. The
  documented schema now includes `client_id` indexes to keep this security path
  fast on large token tables; existing deployments should add the documented
  concurrent indexes before relying on frequent client-wide revocation.

## 0.8.1

### Added

- Token storage now reports misconfiguration through a dedicated exception
  hierarchy rooted at `StorageError`: `StorageConfigError` (no database URL),
  `SchemaDriftError` (an existing token table is missing a required column), and
  `StorageNotInitializedError` (a storage method called before `initialize()`).
  Previously every one of these arrived as a bare `RuntimeError` or
  `ValueError` — indistinguishable from each other and, more importantly,
  awkward to separate from the `asyncpg`/`OSError` failures a transient database
  problem raises. A server that wants to retry or degrade on a database blip but
  refuse to start on a misconfiguration had to match on the message text to tell
  the two apart; it can now branch on the type. Each class also subclasses the
  builtin its condition raised before, so existing `except RuntimeError` /
  `except ValueError` handlers are unaffected. The README's new "Storage errors"
  section documents the hierarchy and shows the recommended startup pattern.

### Fixed

- The README's "Schema versioning and upgrades" section claimed "the schema has
  not changed since it was first published" a few paragraphs above the note that
  0.8.0's at-rest token hashing is a breaking schema change. Someone upgrading
  who stopped at the first claim would conclude there was nothing to do. The
  section now separates a column's *shape* from its *contents* and carries an
  "Upgrading to 0.8.0" block stating that no `ALTER TABLE` is needed, that every
  pre-0.8.0 row is unreadable, and how to clear the dead rows immediately rather
  than waiting out their TTL.

## 0.8.0

### Added

- Documented the schema-upgrade path for `PostgresTokenStorage`. The README's
  new "Schema versioning and upgrades" section explains that
  `CREATE TABLE IF NOT EXISTS` is a no-op on an existing table (so re-running
  the DDL after an upgrade never adds new columns), states the current minimum
  schema, and provides the `ALTER TABLE ... ADD COLUMN IF NOT EXISTS` template
  future column additions will ship. As a backstop, `initialize()` now runs a
  lightweight `information_schema` check and raises a clear error naming any
  required column missing from an existing token table, so schema drift fails
  fast at startup instead of surfacing as a mid-request `UndefinedColumnError`.
  ([#48](https://github.com/brooksmcmillin/mcp-authflow/issues/48))
- Documented DDL now creates an index on `expires_at` for both
  `mcp_access_tokens` and `mcp_refresh_tokens`. Expiry checks on load and the
  `cleanup_expired_tokens` / `cleanup_expired_refresh_tokens` sweeps
  (`DELETE ... WHERE expires_at < now()`) previously seq-scanned, degrading and
  contending with auth traffic on large token tables. The README also shows the
  `CREATE INDEX CONCURRENTLY` form for adding the index to an existing live
  table without an `ACCESS EXCLUSIVE` lock.
  ([#47](https://github.com/brooksmcmillin/mcp-authflow/issues/47))
- New README section "Choosing a `user_id` column type" documents that the
  documented `user_id INTEGER` is only a default for a `SERIAL` user table, and
  gives the `BIGINT` / `UUID` / `TEXT` variants for consumers whose user primary
  key is not a 32-bit integer. It also notes that `user_id` is intentionally
  unindexed (nothing in the library looks tokens up by user) and provides the
  `CREATE INDEX CONCURRENTLY` statements to add if an application introduces a
  per-user lookup.
  ([#49](https://github.com/brooksmcmillin/mcp-authflow/issues/49))

### Changed

- `JWTClientAuthenticator.authenticate()` now logs a WARNING when
  `private_key_jwt` authentication is rejected, instead of only logging
  successes at INFO. Every failure path — replay detection, blocked or
  disallowed algorithm, subject mismatch, expired or too-old assertion, invalid
  audience/issuer, unresolvable JWKS — is covered, matching the WARNING-on-
  rejection behaviour the registration handler already had. Only the
  `client_id` and the error message are logged; the assertion itself never is.
  ([#53](https://github.com/brooksmcmillin/mcp-authflow/issues/53))
- `store_token()` and `store_refresh_token()` now accept `user_id: int | str |
  None` instead of `int | None`, exported as the `mcp_authflow.UserId` alias.
  The value is stored and returned verbatim, so a UUID or opaque-subject user
  key no longer needs a cast or a type-ignore at the call site. Existing
  integer callers are unaffected.
  ([#49](https://github.com/brooksmcmillin/mcp-authflow/issues/49))

### Removed

- Dropped `aiohttp`, `mcp`, `pydantic`, and `pydantic-settings` from
  `[project.dependencies]`. None of them were imported anywhere in the package,
  and they pulled a sizeable transitive tree (`click`, `httpx`, `uvicorn`,
  `yarl`, ...) into every install. The matching `DEP002` deptry ignore is gone
  too, so the check now runs unsuppressed. Installs are unaffected unless a
  consumer was relying on this package to pull those in transitively, in which
  case declare them directly.
  ([#54](https://github.com/brooksmcmillin/mcp-authflow/issues/54))

### Fixed

- `build_device_authorization_response` now composes the fallback
  `verification_uri_complete` with `urllib.parse` instead of string
  concatenation. A configured `verification_uri` that already contains a query
  string or fragment previously produced a malformed complete-URI (e.g. a
  second `?`); the `code` parameter is now URL-encoded and merged into any
  existing query, preserving fragments (CWE-20).
  ([#46](https://github.com/brooksmcmillin/mcp-authflow/issues/46))

### Security

- Bumped the locked `click` version to `>=8.3.3` (now `8.4.2`) to clear
  CVE-2026-7246 (PYSEC-2026-2132 / GHSA-47fr-3ffg-hgmw), a command injection in
  `click.edit()`. Reachability is low: `mcp_authflow` never imports `click` —
  it enters only transitively via `uvicorn` and `mkdocs` — and this library
  never calls `click.edit()`. As a library the `uv.lock` pin does not propagate
  to downstream consumers, who resolve their own `click` version.
  ([#55](https://github.com/brooksmcmillin/mcp-authflow/issues/55))
- The `private_key_jwt` replay cache now caps entry lifetime instead of
  trusting the client assertion's `exp`. A validly-signed client could set `exp`
  far in the future and stream unique-`jti` assertions, growing the replay cache
  (Redis TTL or in-memory dict) without bound (CWE-770). Both
  `_check_and_record_jti_redis` and the in-memory path now clamp the TTL to the
  new `JWT_REPLAY_CACHE_MAX_TTL_SECONDS` ceiling
  (`JWT_MAX_LIFETIME_SECONDS + JWT_MAX_CLOCK_SKEW_SECONDS`), beyond which the
  independent `iat`-age check already rejects a re-presented assertion.
  ([#43](https://github.com/brooksmcmillin/mcp-authflow/issues/43))
- The in-memory sliding-window rate limiter now evicts idle client keys.
  Previously `SlidingWindowRateLimiter` only filtered expired timestamps on a
  per-client request, so a caller that stopped calling (or rotated source IPs,
  since the registration handler keys the limiter on client IP) left stale keys
  in the backing dict forever, growing it unboundedly (CWE-770). A throttled
  sweep (at most once per window) drops keys whose requests have all aged out,
  and `get_retry_after` no longer autovivifies a key for an unknown client. The
  Redis-backed path already bounds memory via key TTLs and is unchanged.
  ([#45](https://github.com/brooksmcmillin/mcp-authflow/issues/45))
- The PKCE helpers gained an opt-in S256-only policy: `verify_pkce` and
  `validate_code_challenge_method` accept `allow_plain=False` to reject the
  `plain` method, which OAuth 2.1 and RFC 9700 deprecate (CWE-757). The new
  `S256_ONLY_CODE_CHALLENGE_METHODS` constant mirrors
  `ALLOWED_CODE_CHALLENGE_METHODS` for metadata/capability advertisement.
  Defaults are unchanged — `plain` is still accepted unless the flag is
  passed — but servers SHOULD opt in unless a legacy client genuinely cannot
  compute S256. ([#44](https://github.com/brooksmcmillin/mcp-authflow/issues/44))
- Token storage now hashes access and refresh tokens at rest. Both
  `PostgresTokenStorage` and `MemoryTokenStorage` key records on the SHA-256
  digest of the token instead of the raw secret, so a database compromise no
  longer yields directly replayable credentials (CWE-312 / CWE-522). The public
  `store_token` / `load_token` API is unchanged — hashing is internal. This is a
  breaking change to the persisted PostgreSQL schema (the `token` column now
  holds a 64-character digest); see the README for migration guidance.

## 0.7.0

### Added

- `build_register_handler` gained three Dynamic Client Registration hardening
  hooks: `auth_validator` (RFC 7591 §3.1 initial-access-token gate, returns
  `401` on failure), `redirect_uri_validator` (defaults to an https-only policy
  with an http loopback exception per OAuth 2.1 §9.7; overridable or
  disable-able), and `get_client_ip` (resolve the rate-limit key from a trusted
  proxy header instead of the direct TCP peer).
- `TokenStorage`, `MemoryTokenStorage`, and `PostgresTokenStorage` now expose
  async `get_refresh_token_count()` for refresh-token inventory.

### Changed

- `rate_limit_exceeded()` now emits the `too_many_requests` OAuth error code
  instead of `slow_down`. The shared `slow_down` code collided with the
  device-flow polling signal that RFC 8628 §3.5 reserves for `slow_down`, so a
  generic 429 (e.g. from registration or introspection rate limiting) could push
  a client into device-flow backoff. Clients that branch on the `error` field of
  a 429 response should match `too_many_requests`.

- Deduplicated the access/refresh token methods in both storage backends. Each
  backend now has generic `_store_to` / `_load_from` / `_delete_from` /
  `_cleanup_from` helpers parameterized by target dict (memory) or table name
  (postgres), and the Postgres pool guard is centralized in `_require_pool()`.
  This removes the four near-identical method pairs (and, in Postgres, the
  repeated pool guard) that had already begun to drift. No behavioral or
  public-API change.

- Refactored `_verify_jwt` and `_find_signing_key` in the `private_key_jwt`
  client authenticator to lower cyclomatic complexity (both were CC 14). Signature
  decoding plus its exception translation now lives in
  `_decode_and_validate_claims`, and JWKS key selection is driven by a
  `_key_matches` predicate backed by an algorithm-family→`kty` map. No behavioral
  change to successful verification.

- `generate_user_code()` now rejects configurations with less than 20 bits of
  entropy, as recommended by RFC 8628 section 6.1. Callers using unusually short
  custom code formats must increase `groups` or `group_size`.

- Custom `TokenStorage` subclasses must now implement
  `get_refresh_token_count()` because it is part of the abstract storage
  interface; subclasses that omit it can no longer be instantiated.

- `mcp_authflow.__version__` is now read from installed distribution metadata.
  Imports directly from an uninstalled source tree report `0.0.0+unknown`.

### Fixed

- Docs: rate-limiter examples in the README and Quick Start now `await`
  `SlidingWindowRateLimiter.is_allowed()` and `get_retry_after()` (both async
  since 0.3.0). The previous snippets called the coroutines without `await`, so
  copy-pasted code silently never rate-limited (`if not <coroutine>` is always
  false).
- Docs: the Quick Start and Configuration guides no longer claim
  `PostgresTokenStorage.initialize()` creates the database schema — it only
  opens the connection pool. Both now point at the manual DDL in the README.

### Security

- Raised the Starlette runtime dependency floor to `1.0.1` to include the fix
  for PYSEC-2026-161, a Host-header authentication bypass.
- CORS responses now include `Vary: Origin` so shared caches cannot reuse an
  allowed origin for a different requester, and preflight responses restrict
  `Access-Control-Allow-Headers` to `Authorization`, `Content-Type`, and
  `Accept` instead of allowing every header.
- Token lifecycle DEBUG logs no longer emit a raw `token[:20]` prefix. Both the
  in-memory and PostgreSQL storage backends now log a non-reversible
  `fp:<sha256[:8]>` fingerprint (new `mcp_authflow.storage.base.token_fingerprint`
  helper), so a readable debug log no longer shrinks a token's offline search
  space while remaining correlatable across log lines.
- `private_key_jwt` JWKS key selection now enforces the `kty` guard for `PS*`
  (RSASSA-PSS) assertions, which previously skipped the key-type check because
  only `RS*`/`ES*` prefixes were mapped. Defense in depth: a `PS256` assertion
  will no longer match a non-RSA JWKS entry that happens to share the `kid`.
- Dynamic Client Registration now validates `redirect_uris` by default,
  rejecting `javascript:`/`data:`/non-loopback `http`/fragment-bearing URIs that
  could enable open-redirect or authorization-code theft. The registration
  endpoint can now require an initial access token via `auth_validator`, and the
  per-IP rate limiter can key on the real client behind a reverse proxy.

## 0.6.0

### New: Device Authorization Grant (RFC 8628)

Adds `mcp_authflow.device` — sans-IO authorization-server primitives for the
device flow. The framework owns the protocol logic; consumers own storage.

```python
from mcp_authflow import (
    DEVICE_CODE_GRANT_TYPE,
    DevicePollDecisionKind,
    build_device_authorization_response,
    evaluate_device_poll,
    generate_device_code,
    generate_user_code,
    normalize_user_code,
)
from mcp_authflow.responses import (
    access_denied,
    authorization_pending,
    expired_token,
    invalid_grant,
    slow_down,
)

# /device/code
response = build_device_authorization_response(
    device_code=generate_device_code(),
    user_code=generate_user_code(),
    verification_uri="https://auth.example.com/device",
    expires_in=600,
    interval=5,
)

# /token (grant_type=urn:ietf:params:oauth:grant-type:device_code)
record = await store.lookup_by_device_code(device_code)
decision = evaluate_device_poll(
    record,
    presented_device_code=device_code,
    presented_client_id=client_id,
)
match decision.kind:
    case DevicePollDecisionKind.APPROVED:
        ...  # mint access token
    case DevicePollDecisionKind.AUTHORIZATION_PENDING:
        return authorization_pending()
    case DevicePollDecisionKind.SLOW_DOWN:
        return slow_down("Polling too fast", retry_after=decision.retry_after)
    case DevicePollDecisionKind.EXPIRED_TOKEN:
        return expired_token()
    case DevicePollDecisionKind.ACCESS_DENIED:
        return access_denied("User denied")
    case DevicePollDecisionKind.INVALID_GRANT:
        return invalid_grant("Unknown device_code")
```

- `evaluate_device_poll` — pure RFC 8628 §3.5 state machine. Constant-time
  device-code compare, client binding, expiry, polling-interval enforcement,
  status mapping. Returns a `DevicePollDecision`; caller decides the response.
- `generate_device_code` — `secrets.token_hex`-based.
- `generate_user_code` — unambiguous-consonant alphabet
  (`BCDFGHJKLMNPQRSTVWXZ`, ~34.6 bits for an 8-char code), configurable
  grouping.
- `normalize_user_code` — canonicalize user-entered codes for lookup
  (accepts `wdjbmjht`, `wdjb mjht`, `WDJB-MJHT`).
- `build_device_authorization_response` — RFC 8628 §3.2 dict assembly.
- `DeviceCodeRecord` — `Protocol` describing the fields the framework reads.
- `DeviceCodeStatus`, `DevicePollDecisionKind` — `StrEnum`s.
- `DEVICE_CODE_GRANT_TYPE` — the URN constant.

### New: PKCE (RFC 7636) verification and validation

Adds `mcp_authflow.pkce` — authorization-server-side primitives for
Proof Key for Code Exchange.

```python
from mcp_authflow import verify_pkce, validate_code_challenge_method

if not validate_code_challenge_method(method):
    raise InvalidRequest("unsupported code_challenge_method")

if not verify_pkce(code_verifier, stored_challenge, method):
    raise InvalidGrant("PKCE verification failed")
```

- `verify_pkce(code_verifier, code_challenge, method)` — constant-time
  check supporting `S256` and `plain`. Unknown methods return `False`.
- `validate_code_verifier` / `validate_code_challenge` — RFC 7636 §4.1/§4.2
  length (43-128) and unreserved-charset checks.
- `validate_code_challenge_method` — allowlist of `{"S256", "plain"}`.
- `ALLOWED_CODE_CHALLENGE_METHODS` — the frozen set for direct use.

Client-side `code_verifier`/`code_challenge` *generation* is intentionally
out of scope; mcp-authflow remains an authorization-server framework.

### New: RFC-aligned error response helpers

`mcp_authflow.responses` gains the missing RFC 6749 / RFC 7591 / RFC 8628
error constructors so callers can stop hand-rolling them:

- `unsupported_grant_type(description)` — RFC 6749 §5.2.
- `access_denied(description)` — RFC 6749 / RFC 8628.
- `invalid_redirect_uri(description)` — RFC 7591 §3.2.2.
- `authorization_pending(description="Authorization pending")` — RFC 8628 §3.5.
- `expired_token(description="Device code has expired")` — RFC 8628 §3.5.
- `pkce_required(description="PKCE is required for public clients")` —
  emits `invalid_request` per OAuth 2.1 / RFC 9700 guidance.

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
