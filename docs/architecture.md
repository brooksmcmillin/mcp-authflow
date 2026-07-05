# Architecture

`mcp-authflow` is the **authorization server** half of the standard OAuth 2.0 split. It mints tokens and answers introspection queries for resource servers.

## The full picture

```
                         MCP Client (Claude, etc.)
                                |
                  1. Authorization request
                                |
                                v
                    +---------------------+
                    |   Auth Server       |   <-- mcp-authflow
                    |                     |
                    |   /token            |   2. Issues access token
                    |   /introspect       |   4. Validates token
                    +---------------------+
                                ^
                                |
                     4. Token introspection (RFC 7662)
                                |
                    +---------------------+
                    |   Resource Server   |   <-- mcp-authflow-resource
                    |   (MCP tools)       |
                    |                     |
                    |  3. Client calls    |
                    |     MCP tools with  |
                    |     Bearer token    |
                    +---------------------+
```

1. **MCP client authenticates** with the auth server (the `/token` endpoint).
2. **Auth server issues an access token**, persisted via a [`TokenStorage`][mcp_authflow.storage.TokenStorage] backend.
3. **Client calls MCP tools** on the resource server with the Bearer token.
4. **Resource server validates the token** by calling the auth server's `/introspect` endpoint ([RFC 7662](https://datatracker.ietf.org/doc/html/rfc7662)).

## Why this split exists

OAuth 2.0 separates authorization (who is the caller, what can they do) from resource access (the actual API). This package implements the authorization half. It tracks clients, tokens, scopes, and expirations, and knows nothing about your MCP tools. That separation lets you:

- Run one auth server in front of many resource servers, and swap any of them without re-auth.
- Replace `mcp-authflow` with a third-party identity provider later, since the contract between auth and resource servers is just RFC 7662.

## What's in the package

| Module | Responsibility |
|---|---|
| [`storage`](api/storage.md) | Persist access and refresh tokens (memory or PostgreSQL). |
| [`registration`](api/registration.md) | RFC 7591 Dynamic Client Registration handler and registry. |
| [`client_auth`](api/client-auth.md) | RFC 7523 `private_key_jwt` client authentication. |
| [`pkce`](api/pkce.md) | RFC 7636 PKCE verification and validation. |
| [`device`](api/device.md) | RFC 8628 Device Authorization Grant primitives. |
| [`responses`](api/responses.md) | RFC 6749 error response helpers. |
| [`rate_limiting`](api/rate-limiting.md) | Sliding-window limits for the token endpoint. |
| [`validation`](api/validation.md) | Input sanitization for client IDs, scopes, etc. |
| [`cors`](api/cors.md) | Origin allowlisting for browser-based MCP clients. |

What `mcp-authflow` deliberately does **not** provide:

- A user-facing login UI. Authorization-code flows still need your own consent page.
- Identity. Bring your own user store; this package only manages tokens issued to clients.
- An opinionated routing layer. Wire the helpers into Starlette / FastAPI / your framework of choice.
- Scope-to-permission mapping. Scopes are stored and returned as opaque strings; deciding which scopes gate which tool calls is the resource server's job.

## Token introspection contract

A resource server (e.g. one built with `mcp-authflow-resource`) POSTs a token to `/introspect`. Your auth server should respond with the active state and metadata:

```json
{
  "active": true,
  "client_id": "demo-client",
  "scope": "read write",
  "exp": 1700000000,
  "aud": "https://mcp.example.com"
}
```

When the token is missing, expired, or revoked, return `{"active": false}` with HTTP 200. See the [Quickstart](quickstart.md) for a full example.

The `aud` field is the [RFC 8707](https://datatracker.ietf.org/doc/html/rfc8707) resource binding. If you set it, the resource server can confirm the `aud` claim matches its own URL, blocking cross-service token replay.
