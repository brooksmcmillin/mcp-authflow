"""RFC 7591 Dynamic Client Registration components."""

from __future__ import annotations

from mcp_authflow.registration.base import (
    ClientRegistrationRequest,
    ClientRegistry,
    RegisteredClient,
)
from mcp_authflow.registration.handler import build_register_handler
from mcp_authflow.registration.memory import MemoryClientRegistry

__all__ = [
    "ClientRegistrationRequest",
    "ClientRegistry",
    "MemoryClientRegistry",
    "RegisteredClient",
    "build_register_handler",
]
