"""Abstract base classes and models for RFC 7591 Dynamic Client Registration."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field


@dataclass(frozen=True)
class ClientRegistrationRequest:
    """Parsed and normalized RFC 7591 registration request.

    Only the fields used by the handler are modeled; additional metadata
    received in the request body is preserved in ``extra`` for adapters
    that want to forward it to a backend.
    """

    client_name: str | None
    redirect_uris: list[str]
    grant_types: list[str]
    response_types: list[str]
    token_endpoint_auth_method: str
    scope: str | None
    extra: dict[str, object] = field(default_factory=dict)

    @property
    def is_public_client(self) -> bool:
        """True if the requested auth method indicates a public client."""
        return self.token_endpoint_auth_method == "none"  # noqa: S105  # nosec B105


@dataclass(frozen=True)
class RegisteredClient:
    """An OAuth client that has been issued credentials.

    Returned by ``ClientRegistry.create_client``. ``client_secret`` is
    ``None`` for public clients (``token_endpoint_auth_method == "none"``).
    """

    client_id: str
    client_secret: str | None
    client_name: str | None
    redirect_uris: list[str]
    grant_types: list[str]
    response_types: list[str]
    token_endpoint_auth_method: str
    scope: str | None
    client_id_issued_at: int
    client_secret_expires_at: int = 0  # 0 = never expires (RFC 7591 §3.2.1)


class ClientRegistry(ABC):
    """Persistence interface for dynamically registered OAuth clients.

    Implementations decide where clients live (in-memory, database,
    delegated to an upstream identity service). The handler factory in
    :mod:`mcp_authflow.registration.handler` is storage-agnostic and
    drives this interface.
    """

    @abstractmethod
    async def create_client(self, request: ClientRegistrationRequest) -> RegisteredClient:
        """Issue credentials for a new client and persist it.

        Implementations are responsible for generating ``client_id`` and,
        for confidential clients, ``client_secret``.
        """
        ...

    @abstractmethod
    async def get_client(self, client_id: str) -> RegisteredClient | None:
        """Look up a previously registered client by id."""
        ...
