# Registration

RFC 7591 Dynamic Client Registration. `build_register_handler` assembles a
Starlette endpoint that parses a registration request, applies host-supplied
policy, and delegates persistence to a pluggable `ClientRegistry`.

::: mcp_authflow.registration
    options:
      members: false
      show_root_heading: false
      show_root_toc_entry: false

## build_register_handler

::: mcp_authflow.registration.handler.build_register_handler

## ClientRegistry

::: mcp_authflow.registration.base.ClientRegistry

## ClientRegistrationRequest

::: mcp_authflow.registration.base.ClientRegistrationRequest

## RegisteredClient

::: mcp_authflow.registration.base.RegisteredClient

## MemoryClientRegistry

::: mcp_authflow.registration.memory.MemoryClientRegistry
