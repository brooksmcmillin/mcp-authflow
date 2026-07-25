"""Token storage abstractions and implementations.

``PostgresTokenStorage`` is importable from this module but loaded lazily
so that ``asyncpg`` is only required when actually used.  Install the
``postgres`` extra to enable it: ``pip install mcp-authflow[postgres]``
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from mcp_authflow.storage.base import TokenStorage, UserId
from mcp_authflow.storage.memory import MemoryTokenStorage

if TYPE_CHECKING:
    from mcp_authflow.storage.postgres import PostgresTokenStorage

__all__ = [
    "TokenStorage",
    "MemoryTokenStorage",
    "PostgresTokenStorage",
    "UserId",
]


def __getattr__(name: str) -> type:
    if name == "PostgresTokenStorage":
        from mcp_authflow.storage.postgres import PostgresTokenStorage  # noqa: PLC0415

        return PostgresTokenStorage
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
