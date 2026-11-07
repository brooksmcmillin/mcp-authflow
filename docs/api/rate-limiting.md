# Rate Limiting

Redis-backed admission uses one atomic Lua script to prune expired requests,
check the limit, and record an allowed request with a key expiry. Concurrent
callers sharing Redis cannot exceed the configured per-client window limit.
Denied requests do not add entries or refresh the key expiry.

Redis clients and custom adapters must support `EVAL` as well as
`ZREMRANGEBYSCORE` and `ZRANGE` for retry-after queries. Redis ACLs must allow
`EVAL` and the script's `ZREMRANGEBYSCORE`, `ZCARD`, `ZADD`, and `EXPIRE` commands.
Script errors propagate to the caller; admission does not fall back to
non-atomic commands or local state.

::: mcp_authflow.rate_limiting
