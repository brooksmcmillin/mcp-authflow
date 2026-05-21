"""In-memory ClientRegistry implementation for testing and development."""

from __future__ import annotations

import secrets
import time

from mcp_authflow.registration.base import (
    ClientRegistrationRequest,
    ClientRegistry,
    RegisteredClient,
)


class MemoryClientRegistry(ClientRegistry):
    """Process-local client registry. Not persistent across restarts."""

    def __init__(self) -> None:
        self._clients: dict[str, RegisteredClient] = {}

    async def create_client(self, request: ClientRegistrationRequest) -> RegisteredClient:
        client_id = f"mcp-{secrets.token_urlsafe(16)}"
        client_secret = None if request.is_public_client else secrets.token_urlsafe(32)
        client = RegisteredClient(
            client_id=client_id,
            client_secret=client_secret,
            client_name=request.client_name,
            redirect_uris=list(request.redirect_uris),
            grant_types=list(request.grant_types),
            response_types=list(request.response_types),
            token_endpoint_auth_method=request.token_endpoint_auth_method,
            scope=request.scope,
            client_id_issued_at=int(time.time()),
        )
        self._clients[client_id] = client
        return client

    async def get_client(self, client_id: str) -> RegisteredClient | None:
        return self._clients.get(client_id)
