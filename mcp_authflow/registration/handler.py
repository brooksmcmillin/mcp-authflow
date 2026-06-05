"""RFC 7591 Dynamic Client Registration handler factory.

Builds a Starlette endpoint that parses a registration request, applies
host-supplied policy (default scope, redirect-URI rewriting, naming),
delegates persistence to a :class:`ClientRegistry`, and returns the
RFC 7591 response.

The handler is intentionally storage-agnostic: deployment-specific
concerns (backend persistence, in-memory caches, scope policy) are
injected by the caller.
"""

from __future__ import annotations

import json
import logging
from collections.abc import Awaitable, Callable, Iterable, Sequence
from typing import Any
from urllib.parse import urlparse

from starlette.requests import Request
from starlette.responses import JSONResponse, Response

from mcp_authflow.rate_limiting import SlidingWindowRateLimiter
from mcp_authflow.registration.base import (
    ClientRegistrationRequest,
    ClientRegistry,
    RegisteredClient,
)
from mcp_authflow.responses import (
    invalid_client,
    invalid_redirect_uri,
    invalid_request,
    rate_limit_exceeded,
    server_error,
)

logger = logging.getLogger(__name__)

# RFC 7591 §2 — token_endpoint_auth_method values this handler emits.
_AUTH_METHOD_PUBLIC = "none"
_AUTH_METHOD_CONFIDENTIAL = "client_secret_post"  # noqa: S105  # nosec B106

# Hosts for which a plaintext http redirect_uri is allowed (OAuth 2.1 §9.7 /
# RFC 8252 §7.3 loopback exception). Everything else must be https.
_LOOPBACK_HOSTS = frozenset({"localhost", "127.0.0.1", "::1"})

# Hook signatures
RedirectUriRewriter = Callable[[list[str]], list[str]]
ClientNameFactory = Callable[[ClientRegistrationRequest], str]
PostRegisterHook = Callable[[RegisteredClient], Awaitable[None]]
RegistrationAuthValidator = Callable[[Request], Awaitable[bool]]
RedirectUriValidator = Callable[[str], bool]
ClientIpResolver = Callable[[Request], str]


def _default_client_ip(request: Request) -> str:
    """Resolve the rate-limit key from the direct TCP peer.

    Deliberately ignores ``X-Forwarded-For``: trusting a client-supplied
    header without a vetted proxy allowlist lets an attacker forge a fresh
    key per request and bypass the limiter. Deployments behind a reverse
    proxy / load balancer / k8s ingress should run Starlette's
    ``ProxyHeadersMiddleware`` (or pass a custom ``get_client_ip`` that
    consults ``X-Forwarded-For`` only for explicitly trusted proxy CIDRs).
    """
    return request.client.host if request.client else "unknown"


def _default_redirect_uri_valid(uri: str) -> bool:
    """Default RFC 7591 / OAuth 2.1 §9.7 redirect_uri policy.

    Accepts absolute ``https`` URIs and ``http`` only for loopback hosts.
    Rejects ``javascript:``, ``data:``, scheme-relative, host-less, and
    fragment-bearing URIs, which otherwise enable open-redirect,
    authorization-code theft, or stored-XSS if the authorization endpoint
    trusts registered URIs without re-validating them.
    """
    try:
        parsed = urlparse(uri)
    except ValueError:
        return False
    if parsed.fragment:
        return False
    scheme = parsed.scheme.lower()
    if scheme == "https":
        return bool(parsed.hostname)
    if scheme == "http":
        return parsed.hostname in _LOOPBACK_HOSTS
    return False


def build_register_handler(
    registry: ClientRegistry,
    *,
    default_scope: str,
    rate_limiter: SlidingWindowRateLimiter | None = None,
    auth_validator: RegistrationAuthValidator | None = None,
    get_client_ip: ClientIpResolver | None = None,
    default_redirect_uris: Sequence[str] = (),
    redirect_uri_rewriters: Iterable[RedirectUriRewriter] = (),
    redirect_uri_validator: RedirectUriValidator | None = _default_redirect_uri_valid,
    client_name_factory: ClientNameFactory | None = None,
    post_register_hooks: Iterable[PostRegisterHook] = (),
) -> Callable[[Request], Awaitable[Response]]:
    """Return a Starlette handler implementing RFC 7591 registration.

    Args:
        registry: Persistence backend that issues and stores clients.
        default_scope: Scope granted when the request omits one. Also
            included in the registration response.
        rate_limiter: Optional per-IP limiter applied before parsing.
            Skipped when ``None`` (tests / trusted networks).
        auth_validator: Optional async callable gating the endpoint
            (RFC 7591 §3.1 initial access token). Invoked before the
            rate-limit check; a falsy return yields ``401`` and the
            request is not processed. When ``None`` the endpoint is open
            (rate limiting is not authentication) — production
            deployments SHOULD configure this.
        get_client_ip: Resolves the rate-limit key from the request.
            Defaults to the direct TCP peer (``request.client.host``),
            which is the proxy IP behind a reverse proxy / LB / ingress.
            Pass a callable that consults ``X-Forwarded-For`` only for
            explicitly trusted proxy CIDRs (or run
            ``ProxyHeadersMiddleware``) to key on the real client.
        default_redirect_uris: Fallback ``redirect_uris`` if the request
            sends none. Empty by default — most deployments should set
            this or reject requests that omit URIs.
        redirect_uri_rewriters: Ordered list of callables applied to the
            ``redirect_uris`` list. Each receives and returns the list,
            allowing additions (e.g. debug-variant expansion) or
            normalization.
        redirect_uri_validator: Predicate applied to each redirect_uri
            after rewriting; any URI returning falsy is rejected with
            ``invalid_redirect_uri`` (400). Defaults to an https-only
            policy (http allowed for loopback hosts) per OAuth 2.1 §9.7.
            Pass ``None`` to disable validation, or a custom predicate to
            override the policy (e.g. to allow native-app custom schemes).
        client_name_factory: Override the client name. Receives the
            parsed request; returns the name to assign. When ``None``
            the request's ``client_name`` (or a registry-supplied
            default) is used.
        post_register_hooks: Async callables invoked with the newly
            issued ``RegisteredClient`` after persistence (e.g. to
            populate an in-process cache).
    """
    rewriters = list(redirect_uri_rewriters)
    hooks = list(post_register_hooks)
    defaults = list(default_redirect_uris)
    client_ip_of = get_client_ip or _default_client_ip

    async def register_handler(request: Request) -> Response:
        if auth_validator is not None and not await auth_validator(request):
            logger.warning("DCR request: authorization rejected")
            return invalid_client("Registration not authorized")

        if rate_limiter is not None:
            caller_ip = client_ip_of(request)
            if not await rate_limiter.is_allowed(caller_ip):
                retry_after = await rate_limiter.get_retry_after(caller_ip)
                return rate_limit_exceeded("Too many registration requests", retry_after)

        try:
            body = await request.body()
            payload: dict[str, Any] = json.loads(body) if body else {}
        except json.JSONDecodeError as e:
            logger.warning("DCR request: invalid JSON (%s)", e)
            return invalid_request("Invalid JSON")

        if not isinstance(payload, dict):
            return invalid_request("Request body must be a JSON object")

        logger.info(
            "DCR request: client_name=%r grant_types=%r redirect_uris=%r",
            payload.get("client_name"),
            payload.get("grant_types"),
            payload.get("redirect_uris"),
        )

        redirect_uris = list(payload.get("redirect_uris") or [])
        for rewriter in rewriters:
            redirect_uris = rewriter(redirect_uris)
        if not redirect_uris:
            redirect_uris = list(defaults)

        if redirect_uri_validator is not None:
            for uri in redirect_uris:
                if not redirect_uri_validator(uri):
                    logger.warning("DCR request: rejected redirect_uri %r", uri)
                    return invalid_redirect_uri(f"Invalid redirect_uri: {uri}")

        grant_types, auth_method = _derive_grant_types_and_auth_method(
            payload.get("grant_types") or []
        )
        response_types = list(payload.get("response_types") or ["code"])
        scope = payload.get("scope") or default_scope

        parsed = ClientRegistrationRequest(
            client_name=payload.get("client_name"),
            redirect_uris=redirect_uris,
            grant_types=grant_types,
            response_types=response_types,
            token_endpoint_auth_method=auth_method,
            scope=scope,
            extra={
                k: v
                for k, v in payload.items()
                if k
                not in {
                    "client_name",
                    "redirect_uris",
                    "grant_types",
                    "response_types",
                    "token_endpoint_auth_method",
                    "scope",
                }
            },
        )
        if client_name_factory is not None:
            parsed = _replace_client_name(parsed, client_name_factory(parsed))

        try:
            client = await registry.create_client(parsed)
        except Exception:
            logger.exception("DCR: registry.create_client failed")
            return server_error("Failed to register client")

        for hook in hooks:
            try:
                await hook(client)
            except Exception:
                logger.exception(
                    "DCR: post_register hook failed for client %s",
                    client.client_id,
                )

        logger.info("DCR: registered client %s", client.client_id)
        return JSONResponse(_build_response_body(client), status_code=201)

    return register_handler


def _derive_grant_types_and_auth_method(
    requested: list[str],
) -> tuple[list[str], str]:
    """Map requested grant_types to (grant_types, token_endpoint_auth_method).

    ``client_credentials`` → confidential machine client.
    Anything else (or unspecified) → public client with auth code +
    refresh + device code (the MCP/Claude Code default).
    """
    if "client_credentials" in requested:
        return ["client_credentials"], _AUTH_METHOD_CONFIDENTIAL
    return (
        ["authorization_code", "refresh_token", "device_code"],
        _AUTH_METHOD_PUBLIC,
    )


def _build_response_body(client: RegisteredClient) -> dict[str, Any]:
    body: dict[str, Any] = {
        "client_id": client.client_id,
        "client_id_issued_at": client.client_id_issued_at,
        "redirect_uris": client.redirect_uris,
        "response_types": client.response_types,
        "grant_types": client.grant_types,
        "token_endpoint_auth_method": client.token_endpoint_auth_method,
    }
    if client.client_name is not None:
        body["client_name"] = client.client_name
    if client.scope is not None:
        body["scope"] = client.scope
    if client.client_secret is not None:
        body["client_secret"] = client.client_secret
        body["client_secret_expires_at"] = client.client_secret_expires_at
    return body


def _replace_client_name(req: ClientRegistrationRequest, name: str) -> ClientRegistrationRequest:
    return ClientRegistrationRequest(
        client_name=name,
        redirect_uris=req.redirect_uris,
        grant_types=req.grant_types,
        response_types=req.response_types,
        token_endpoint_auth_method=req.token_endpoint_auth_method,
        scope=req.scope,
        extra=req.extra,
    )
