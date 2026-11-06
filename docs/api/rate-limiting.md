# Rate Limiting

When configured with Redis, admission atomically prunes expired entries, checks
capacity, records an allowed request, and sets key expiry in one Lua script.
Concurrent callers sharing a key cannot admit more than the configured limit.
Denied requests do not add entries or refresh expiry.

Custom Redis adapters must implement `EVAL`, `ZREMRANGEBYSCORE`, and `ZRANGE`
(the latter two are used by `get_retry_after`). Redis ACLs must permit `EVAL`
and the script's `ZREMRANGEBYSCORE`, `ZCARD`, `ZADD`, and `EXPIRE` commands.
Redis errors propagate to the caller; there is no fallback to process-local state.

::: mcp_authflow.rate_limiting
