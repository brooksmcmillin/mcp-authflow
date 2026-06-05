"""Tests for the RFC 7591 Dynamic Client Registration components."""

from __future__ import annotations

from typing import Any

from starlette.applications import Starlette
from starlette.routing import Route
from starlette.testclient import TestClient

from mcp_authflow.rate_limiting import SlidingWindowRateLimiter
from mcp_authflow.registration import (
    ClientRegistrationRequest,
    MemoryClientRegistry,
    RegisteredClient,
    build_register_handler,
)

DEFAULT_SCOPE = "mcp:tools"


# ---------------------------------------------------------------------------
# MemoryClientRegistry
# ---------------------------------------------------------------------------


class TestMemoryClientRegistry:
    async def test_create_public_client_has_no_secret(self) -> None:
        registry = MemoryClientRegistry()
        req = ClientRegistrationRequest(
            client_name="cli",
            redirect_uris=["http://localhost/cb"],
            grant_types=["authorization_code", "refresh_token"],
            response_types=["code"],
            token_endpoint_auth_method="none",
            scope=DEFAULT_SCOPE,
        )
        client = await registry.create_client(req)

        assert client.client_id.startswith("mcp-")
        assert client.client_secret is None
        assert client.redirect_uris == ["http://localhost/cb"]
        assert client.token_endpoint_auth_method == "none"
        assert client.client_id_issued_at > 0
        assert client.client_secret_expires_at == 0

    async def test_create_confidential_client_has_secret(self) -> None:
        registry = MemoryClientRegistry()
        req = ClientRegistrationRequest(
            client_name="machine",
            redirect_uris=[],
            grant_types=["client_credentials"],
            response_types=["code"],
            token_endpoint_auth_method="client_secret_post",
            scope=DEFAULT_SCOPE,
        )
        client = await registry.create_client(req)

        assert client.client_secret is not None
        assert len(client.client_secret) >= 32

    async def test_get_client_returns_stored_client(self) -> None:
        registry = MemoryClientRegistry()
        req = ClientRegistrationRequest(
            client_name=None,
            redirect_uris=["http://localhost/cb"],
            grant_types=["authorization_code"],
            response_types=["code"],
            token_endpoint_auth_method="none",
            scope=DEFAULT_SCOPE,
        )
        created = await registry.create_client(req)
        fetched = await registry.get_client(created.client_id)
        assert fetched == created

    async def test_get_client_returns_none_for_unknown(self) -> None:
        registry = MemoryClientRegistry()
        assert await registry.get_client("does-not-exist") is None

    async def test_each_client_gets_unique_id(self) -> None:
        registry = MemoryClientRegistry()
        req = ClientRegistrationRequest(
            client_name=None,
            redirect_uris=["http://localhost/cb"],
            grant_types=["authorization_code"],
            response_types=["code"],
            token_endpoint_auth_method="none",
            scope=DEFAULT_SCOPE,
        )
        ids = {(await registry.create_client(req)).client_id for _ in range(5)}
        assert len(ids) == 5


# ---------------------------------------------------------------------------
# build_register_handler
# ---------------------------------------------------------------------------


def _make_client(
    *,
    registry: MemoryClientRegistry | None = None,
    **kwargs: Any,
) -> tuple[TestClient, MemoryClientRegistry]:
    registry = registry or MemoryClientRegistry()
    handler = build_register_handler(registry, default_scope=DEFAULT_SCOPE, **kwargs)
    app = Starlette(routes=[Route("/register", handler, methods=["POST"])])
    return TestClient(app), registry


class TestRegisterHandler:
    def test_returns_201_with_rfc7591_body_for_public_client(self) -> None:
        client, _ = _make_client()
        resp = client.post(
            "/register",
            json={
                "client_name": "cli",
                "redirect_uris": ["http://localhost/cb"],
                "grant_types": ["authorization_code", "refresh_token"],
            },
        )
        assert resp.status_code == 201
        body = resp.json()
        assert body["client_id"].startswith("mcp-")
        assert body["client_id_issued_at"] > 0
        assert body["redirect_uris"] == ["http://localhost/cb"]
        assert body["response_types"] == ["code"]
        assert body["token_endpoint_auth_method"] == "none"
        assert body["scope"] == DEFAULT_SCOPE
        assert body["client_name"] == "cli"
        # Public client: no secret fields.
        assert "client_secret" not in body
        assert "client_secret_expires_at" not in body

    def test_client_credentials_request_yields_confidential_client(
        self,
    ) -> None:
        client, _ = _make_client()
        resp = client.post(
            "/register",
            json={
                "client_name": "machine",
                "grant_types": ["client_credentials"],
            },
        )
        assert resp.status_code == 201
        body = resp.json()
        assert body["grant_types"] == ["client_credentials"]
        assert body["token_endpoint_auth_method"] == "client_secret_post"
        assert isinstance(body["client_secret"], str)
        assert body["client_secret_expires_at"] == 0

    def test_unspecified_grant_types_default_to_public_auth_code_set(
        self,
    ) -> None:
        client, _ = _make_client()
        resp = client.post(
            "/register",
            json={"redirect_uris": ["http://localhost/cb"]},
        )
        body = resp.json()
        assert body["grant_types"] == [
            "authorization_code",
            "refresh_token",
            "device_code",
        ]
        assert body["token_endpoint_auth_method"] == "none"

    def test_default_redirect_uris_used_when_omitted(self) -> None:
        defaults = ["http://localhost:3000/cb", "https://example.com/cb"]
        client, _ = _make_client(default_redirect_uris=defaults)
        resp = client.post("/register", json={})
        body = resp.json()
        assert body["redirect_uris"] == defaults

    def test_redirect_uri_rewriters_run_in_order(self) -> None:
        def add_debug(uris: list[str]) -> list[str]:
            extra = [u.replace("/cb", "/cb/debug") for u in uris if "/cb" in u]
            return uris + [u for u in extra if u not in uris]

        def dedupe(uris: list[str]) -> list[str]:
            seen: list[str] = []
            for u in uris:
                if u not in seen:
                    seen.append(u)
            return seen

        client, _ = _make_client(
            redirect_uri_rewriters=[add_debug, dedupe],
        )
        resp = client.post(
            "/register",
            json={"redirect_uris": ["http://localhost/cb"]},
        )
        body = resp.json()
        assert body["redirect_uris"] == [
            "http://localhost/cb",
            "http://localhost/cb/debug",
        ]

    def test_client_name_factory_overrides_request_name(self) -> None:
        def name_it(req: ClientRegistrationRequest) -> str:
            return f"forced-{req.token_endpoint_auth_method}"

        client, registry = _make_client(client_name_factory=name_it)
        resp = client.post(
            "/register",
            json={"client_name": "ignored", "grant_types": ["client_credentials"]},
        )
        body = resp.json()
        assert body["client_name"] == "forced-client_secret_post"
        stored = list(registry._clients.values())[0]
        assert stored.client_name == "forced-client_secret_post"

    def test_post_register_hooks_receive_client(self) -> None:
        captured: list[RegisteredClient] = []

        async def capture(client: RegisteredClient) -> None:
            captured.append(client)

        http, _ = _make_client(post_register_hooks=[capture])
        resp = http.post("/register", json={"redirect_uris": ["http://localhost/cb"]})
        assert resp.status_code == 201
        assert len(captured) == 1
        assert captured[0].client_id == resp.json()["client_id"]

    def test_failing_post_register_hook_does_not_fail_request(self) -> None:
        async def boom(client: RegisteredClient) -> None:
            raise RuntimeError("hook exploded")

        http, _ = _make_client(post_register_hooks=[boom])
        resp = http.post("/register", json={"redirect_uris": ["http://localhost/cb"]})
        assert resp.status_code == 201

    def test_invalid_json_returns_400(self) -> None:
        client, _ = _make_client()
        resp = client.post(
            "/register",
            content=b"{not json",
            headers={"content-type": "application/json"},
        )
        assert resp.status_code == 400
        assert resp.json()["error"] == "invalid_request"

    def test_non_object_json_returns_400(self) -> None:
        client, _ = _make_client()
        resp = client.post("/register", json=["not", "an", "object"])
        assert resp.status_code == 400
        assert resp.json()["error"] == "invalid_request"

    def test_registry_failure_returns_500(self) -> None:
        class BoomRegistry(MemoryClientRegistry):
            async def create_client(self, request: ClientRegistrationRequest) -> RegisteredClient:
                raise RuntimeError("backend down")

        client, _ = _make_client(registry=BoomRegistry())
        resp = client.post("/register", json={"redirect_uris": ["http://localhost/cb"]})
        assert resp.status_code == 500

    def test_explicit_scope_overrides_default(self) -> None:
        client, _ = _make_client()
        resp = client.post(
            "/register",
            json={
                "redirect_uris": ["http://localhost/cb"],
                "scope": "custom:scope",
            },
        )
        assert resp.json()["scope"] == "custom:scope"

    def test_extra_fields_preserved_on_parsed_request(self) -> None:
        captured: list[ClientRegistrationRequest] = []

        class CapturingRegistry(MemoryClientRegistry):
            async def create_client(self, request: ClientRegistrationRequest) -> RegisteredClient:
                captured.append(request)
                return await super().create_client(request)

        client, _ = _make_client(registry=CapturingRegistry())
        resp = client.post(
            "/register",
            json={
                "redirect_uris": ["http://localhost/cb"],
                "software_id": "abc-123",
                "contacts": ["dev@example.com"],
            },
        )
        assert resp.status_code == 201
        assert captured[0].extra == {
            "software_id": "abc-123",
            "contacts": ["dev@example.com"],
        }


# ---------------------------------------------------------------------------
# Rate limiting
# ---------------------------------------------------------------------------


class TestRateLimiting:
    async def test_blocks_when_limit_exceeded(self) -> None:
        limiter = SlidingWindowRateLimiter(requests_per_window=2, window_seconds=60)
        registry = MemoryClientRegistry()
        handler = build_register_handler(
            registry,
            default_scope=DEFAULT_SCOPE,
            rate_limiter=limiter,
        )
        app = Starlette(routes=[Route("/register", handler, methods=["POST"])])
        http = TestClient(app)

        body: dict[str, Any] = {"redirect_uris": ["http://localhost/cb"]}
        assert http.post("/register", json=body).status_code == 201
        assert http.post("/register", json=body).status_code == 201
        # Third request from the same client IP is blocked.
        third = http.post("/register", json=body)
        assert third.status_code == 429
        # mcp_authflow.responses.rate_limit_exceeded uses the RFC 6749
        # "slow_down" error code per the existing helper.
        assert third.json()["error"] == "slow_down"


class TestAuthValidator:
    def test_rejects_when_validator_returns_false(self) -> None:
        async def deny(request: Any) -> bool:
            return False

        client, registry = _make_client(auth_validator=deny)
        resp = client.post("/register", json={"redirect_uris": ["http://localhost/cb"]})
        assert resp.status_code == 401
        assert resp.json()["error"] == "invalid_client"
        # Request never reached the registry.
        assert registry._clients == {}

    def test_allows_when_validator_returns_true(self) -> None:
        seen: list[str] = []

        async def allow(request: Any) -> bool:
            seen.append(request.headers.get("authorization", ""))
            return True

        client, _ = _make_client(auth_validator=allow)
        resp = client.post(
            "/register",
            json={"redirect_uris": ["http://localhost/cb"]},
            headers={"Authorization": "Bearer initial-access-token"},
        )
        assert resp.status_code == 201
        assert seen == ["Bearer initial-access-token"]

    def test_auth_runs_before_rate_limit(self) -> None:
        # An unauthorized request must be rejected with 401, not 429, even
        # when the limiter would otherwise be the first gate.
        limiter = SlidingWindowRateLimiter(requests_per_window=1, window_seconds=60)

        async def deny(request: Any) -> bool:
            return False

        client, _ = _make_client(auth_validator=deny, rate_limiter=limiter)
        for _ in range(3):
            resp = client.post("/register", json={"redirect_uris": ["http://localhost/cb"]})
            assert resp.status_code == 401


class TestRedirectUriValidation:
    def test_rejects_javascript_scheme_by_default(self) -> None:
        client, _ = _make_client()
        resp = client.post(
            "/register",
            json={"redirect_uris": ["javascript:alert(1)"]},
        )
        assert resp.status_code == 400
        assert resp.json()["error"] == "invalid_redirect_uri"

    def test_rejects_non_loopback_http_by_default(self) -> None:
        client, _ = _make_client()
        resp = client.post(
            "/register",
            json={"redirect_uris": ["http://evil.example.com/cb"]},
        )
        assert resp.status_code == 400
        assert resp.json()["error"] == "invalid_redirect_uri"

    def test_rejects_uri_with_fragment(self) -> None:
        client, _ = _make_client()
        resp = client.post(
            "/register",
            json={"redirect_uris": ["https://example.com/cb#frag"]},
        )
        assert resp.status_code == 400
        assert resp.json()["error"] == "invalid_redirect_uri"

    def test_allows_https_and_loopback_http(self) -> None:
        client, _ = _make_client()
        resp = client.post(
            "/register",
            json={
                "redirect_uris": [
                    "https://app.example.com/cb",
                    "http://localhost:3000/cb",
                    "http://127.0.0.1/cb",
                ]
            },
        )
        assert resp.status_code == 201

    def test_custom_validator_overrides_default(self) -> None:
        client, _ = _make_client(redirect_uri_validator=lambda uri: uri.startswith("com.example."))
        ok = client.post("/register", json={"redirect_uris": ["com.example.app:/cb"]})
        assert ok.status_code == 201
        bad = client.post("/register", json={"redirect_uris": ["https://example.com/cb"]})
        assert bad.status_code == 400

    def test_disabling_validator_allows_anything(self) -> None:
        client, _ = _make_client(redirect_uri_validator=None)
        resp = client.post("/register", json={"redirect_uris": ["javascript:alert(1)"]})
        assert resp.status_code == 201


class TestClientIpResolver:
    async def test_custom_resolver_keys_rate_limit(self) -> None:
        # Two requests with distinct forwarded IPs each get their own bucket,
        # so neither is blocked despite a window of 1.
        limiter = SlidingWindowRateLimiter(requests_per_window=1, window_seconds=60)

        def from_xff(request: Any) -> str:
            return request.headers.get("x-forwarded-for", "unknown")

        registry = MemoryClientRegistry()
        handler = build_register_handler(
            registry,
            default_scope=DEFAULT_SCOPE,
            rate_limiter=limiter,
            get_client_ip=from_xff,
        )
        app = Starlette(routes=[Route("/register", handler, methods=["POST"])])
        http = TestClient(app)

        body: dict[str, Any] = {"redirect_uris": ["http://localhost/cb"]}

        def post(ip: str) -> int:
            return http.post("/register", json=body, headers={"X-Forwarded-For": ip}).status_code

        assert post("1.1.1.1") == 201
        assert post("2.2.2.2") == 201
        # Same forwarded IP a second time is blocked.
        assert post("1.1.1.1") == 429


# Sanity check: the public API surface re-exports what the tests use.
def test_public_api_surface() -> None:
    import mcp_authflow.registration as reg

    for name in (
        "ClientRegistrationRequest",
        "ClientRegistry",
        "MemoryClientRegistry",
        "RegisteredClient",
        "build_register_handler",
    ):
        assert hasattr(reg, name), name
