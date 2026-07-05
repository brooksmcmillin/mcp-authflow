# Device Authorization Grant

Sans-IO building blocks for the RFC 8628 device flow: secure device- and
user-code generators, user-code normalization, the pure `evaluate_device_poll`
state machine for the token endpoint, and the device authorization response
builder. The module does no DB or HTTP I/O — callers own persistence.

::: mcp_authflow.device
