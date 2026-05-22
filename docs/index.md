# mcp-authflow

OAuth 2.0 **Authorization Server** framework for [MCP](https://modelcontextprotocol.io/) servers: issue and manage tokens that protect MCP tool access, and pair with [**mcp-authflow-resource**](https://github.com/brooksmcmillin/mcp-authflow-resource) for the matching resource server.

---

## What's in the box

- **Token storage** with PostgreSQL and in-memory backends
- **RFC 6749** standardized OAuth error responses
- **Sliding-window rate limiting** for token endpoints (in-process or Redis)
- **Input validation** for client IDs and scopes
- **RFC 7636 PKCE** verification (`S256` + `plain`) and input validation
- **CORS helpers** with origin allowlisting
- **Async-first** design, built on Starlette

## Install

```bash
pip install mcp-authflow

# With PostgreSQL token storage (production)
pip install mcp-authflow[postgres]
```

## Where to go next

<div class="grid cards" markdown>

- :material-rocket-launch: **[Quickstart](quickstart.md)**

    Build a working token + introspection endpoint in ~50 lines.

- :material-sitemap: **[Architecture](architecture.md)**

    How the auth server and resource server fit together.

- :material-cog: **[Configuration](configuration.md)**

    Environment variables and storage backends.

- :material-api: **[API Reference](api/index.md)**

    Module-by-module reference, generated from docstrings.

</div>

Start with the Quickstart if you just want to mint and introspect tokens; the Architecture page covers the auth-server / resource-server split in depth.

## How it fits with mcp-authflow-resource

`mcp-authflow` issues tokens; `mcp-authflow-resource` validates them. They communicate via [RFC 7662 token introspection](https://datatracker.ietf.org/doc/html/rfc7662). Either package works on its own. Point `mcp-authflow-resource` at an existing OAuth provider, or run `mcp-authflow` behind a hand-rolled resource server.

## License

[MIT](https://github.com/brooksmcmillin/mcp-authflow/blob/main/LICENSE)
