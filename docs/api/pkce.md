# PKCE

Proof Key for Code Exchange (RFC 7636) authorization-server primitives:
constant-time verification of a `code_verifier` against the bound
`code_challenge`, plus input validation for verifiers, challenges, and the
challenge-method allowlist (`S256`, `plain`).

::: mcp_authflow.pkce
