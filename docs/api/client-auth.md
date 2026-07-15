# Client Authentication

`private_key_jwt` client authentication (RFC 7523) for OAuth 2.0 token
endpoints. Clients sign a JWT with their private key and submit it as a
`client_assertion`; `JWTClientAuthenticator` verifies it against a public key
resolved through a pluggable `JWKSProvider`, with an asymmetric-only algorithm
allowlist and `jti` replay protection.

For a shared replay cache, pass any object satisfying
[`mcp_authflow.client_auth.AsyncRedisClient`][]. This protocol requires only
the Redis `SET` operation used by replay protection; it is intentionally
separate from the sorted-set protocol used by the rate limiter.

::: mcp_authflow.client_auth
