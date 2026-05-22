"""Tests for OAuth error response constructors in responses.py."""

import json
from collections.abc import Callable

import pytest
from starlette.responses import JSONResponse

from mcp_authflow.responses import (
    OAUTH_NO_CACHE_HEADERS,
    access_denied,
    authorization_pending,
    backend_connection_error,
    backend_invalid_response,
    backend_oauth_error,
    backend_timeout,
    expired_token,
    invalid_client,
    invalid_grant,
    invalid_redirect_uri,
    invalid_request,
    invalid_scope,
    oauth_error,
    pkce_required,
    rate_limit_exceeded,
    server_error,
    slow_down,
    unsupported_grant_type,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _body(response: JSONResponse) -> dict[str, str]:
    """Decode the response body as JSON."""
    body = response.body
    if isinstance(body, memoryview):
        return json.loads(bytes(body))
    return json.loads(body)


# ---------------------------------------------------------------------------
# oauth_error (base constructor)
# ---------------------------------------------------------------------------


class TestOauthError:
    def test_default_status_code_is_400(self) -> None:
        response = oauth_error("invalid_request", "bad input")
        assert response.status_code == 400

    def test_error_field_is_set(self) -> None:
        response = oauth_error("invalid_request", "bad input")
        assert _body(response)["error"] == "invalid_request"

    def test_error_description_field_is_set(self) -> None:
        response = oauth_error("invalid_request", "bad input")
        assert _body(response)["error_description"] == "bad input"

    def test_custom_status_code(self) -> None:
        response = oauth_error("server_error", "oops", status_code=500)
        assert response.status_code == 500

    def test_no_cache_header_is_present(self) -> None:
        response = oauth_error("invalid_request", "bad input")
        assert response.headers["cache-control"] == "no-store"

    def test_content_type_is_json(self) -> None:
        response = oauth_error("invalid_request", "bad input")
        assert "application/json" in response.headers["content-type"]

    def test_extra_headers_are_merged(self) -> None:
        response = oauth_error("slow_down", "too fast", extra_headers={"Retry-After": "5"})
        assert response.headers["retry-after"] == "5"

    def test_extra_headers_do_not_remove_cache_control(self) -> None:
        response = oauth_error("slow_down", "too fast", extra_headers={"Retry-After": "5"})
        assert response.headers["cache-control"] == "no-store"

    def test_no_extra_headers_leaves_only_no_cache(self) -> None:
        response = oauth_error("invalid_request", "bad input")
        assert "retry-after" not in response.headers

    def test_body_contains_only_error_and_description_keys(self) -> None:
        body = _body(oauth_error("invalid_request", "bad input"))
        assert set(body.keys()) == {"error", "error_description"}


# ---------------------------------------------------------------------------
# invalid_request
# ---------------------------------------------------------------------------


class TestInvalidRequest:
    def test_status_code_is_400(self) -> None:
        assert invalid_request("missing param").status_code == 400

    def test_error_code(self) -> None:
        assert _body(invalid_request("missing param"))["error"] == "invalid_request"

    def test_description_is_forwarded(self) -> None:
        assert _body(invalid_request("missing param"))["error_description"] == "missing param"

    def test_no_cache_header(self) -> None:
        assert invalid_request("x").headers["cache-control"] == "no-store"


# ---------------------------------------------------------------------------
# invalid_client
# ---------------------------------------------------------------------------


class TestInvalidClient:
    def test_status_code_is_401(self) -> None:
        assert invalid_client("auth failed").status_code == 401

    def test_error_code(self) -> None:
        assert _body(invalid_client("auth failed"))["error"] == "invalid_client"

    def test_description_is_forwarded(self) -> None:
        assert _body(invalid_client("auth failed"))["error_description"] == "auth failed"

    def test_no_cache_header(self) -> None:
        assert invalid_client("x").headers["cache-control"] == "no-store"


# ---------------------------------------------------------------------------
# slow_down
# ---------------------------------------------------------------------------


class TestSlowDown:
    def test_status_code_is_400(self) -> None:
        assert slow_down("polling too fast").status_code == 400

    def test_error_code(self) -> None:
        assert _body(slow_down("polling too fast"))["error"] == "slow_down"

    def test_description_is_forwarded(self) -> None:
        assert _body(slow_down("polling too fast"))["error_description"] == "polling too fast"

    def test_no_retry_after_when_not_provided(self) -> None:
        assert "retry-after" not in slow_down("too fast").headers

    def test_retry_after_header_when_provided(self) -> None:
        assert slow_down("too fast", retry_after=10).headers["retry-after"] == "10"

    def test_retry_after_none_does_not_set_header(self) -> None:
        assert "retry-after" not in slow_down("too fast", retry_after=None).headers

    def test_no_cache_header(self) -> None:
        assert slow_down("too fast").headers["cache-control"] == "no-store"


# ---------------------------------------------------------------------------
# rate_limit_exceeded
# ---------------------------------------------------------------------------


class TestRateLimitExceeded:
    def test_status_code_is_429(self) -> None:
        assert rate_limit_exceeded("too many requests").status_code == 429

    def test_error_code_is_slow_down(self) -> None:
        # rate_limit_exceeded reuses the "slow_down" error code per OAuth spec
        assert _body(rate_limit_exceeded("too many requests"))["error"] == "slow_down"

    def test_description_is_forwarded(self) -> None:
        assert (
            _body(rate_limit_exceeded("too many requests"))["error_description"]
            == "too many requests"
        )

    def test_no_retry_after_when_not_provided(self) -> None:
        assert "retry-after" not in rate_limit_exceeded("rate limited").headers

    def test_retry_after_header_when_provided(self) -> None:
        assert rate_limit_exceeded("rate limited", retry_after=30).headers["retry-after"] == "30"

    def test_no_cache_header(self) -> None:
        assert rate_limit_exceeded("rate limited").headers["cache-control"] == "no-store"


# ---------------------------------------------------------------------------
# server_error
# ---------------------------------------------------------------------------


class TestServerError:
    def test_default_status_code_is_500(self) -> None:
        assert server_error("internal error").status_code == 500

    def test_custom_status_code_502(self) -> None:
        assert server_error("bad gateway", status_code=502).status_code == 502

    def test_custom_status_code_504(self) -> None:
        assert server_error("timeout", status_code=504).status_code == 504

    def test_error_code(self) -> None:
        assert _body(server_error("internal error"))["error"] == "server_error"

    def test_description_is_forwarded(self) -> None:
        assert _body(server_error("internal error"))["error_description"] == "internal error"

    def test_no_cache_header(self) -> None:
        assert server_error("x").headers["cache-control"] == "no-store"


# ---------------------------------------------------------------------------
# backend_timeout
# ---------------------------------------------------------------------------


class TestBackendTimeout:
    def test_status_code_is_504(self) -> None:
        assert backend_timeout().status_code == 504

    def test_error_code(self) -> None:
        assert _body(backend_timeout())["error"] == "server_error"

    def test_description(self) -> None:
        assert _body(backend_timeout())["error_description"] == "Backend timeout"

    def test_no_cache_header(self) -> None:
        assert backend_timeout().headers["cache-control"] == "no-store"


# ---------------------------------------------------------------------------
# backend_connection_error
# ---------------------------------------------------------------------------


class TestBackendConnectionError:
    def test_status_code_is_502(self) -> None:
        assert backend_connection_error().status_code == 502

    def test_error_code(self) -> None:
        assert _body(backend_connection_error())["error"] == "server_error"

    def test_description(self) -> None:
        assert _body(backend_connection_error())["error_description"] == "Backend connection error"

    def test_no_cache_header(self) -> None:
        assert backend_connection_error().headers["cache-control"] == "no-store"


# ---------------------------------------------------------------------------
# backend_invalid_response
# ---------------------------------------------------------------------------


class TestBackendInvalidResponse:
    def test_status_code_is_502(self) -> None:
        assert backend_invalid_response().status_code == 502

    def test_error_code(self) -> None:
        assert _body(backend_invalid_response())["error"] == "server_error"

    def test_description(self) -> None:
        assert (
            _body(backend_invalid_response())["error_description"]
            == "Invalid response from backend"
        )

    def test_no_cache_header(self) -> None:
        assert backend_invalid_response().headers["cache-control"] == "no-store"


# ---------------------------------------------------------------------------
# invalid_grant
# ---------------------------------------------------------------------------


class TestInvalidGrant:
    def test_status_code_is_400(self) -> None:
        assert invalid_grant("code expired").status_code == 400

    def test_error_code(self) -> None:
        assert _body(invalid_grant("code expired"))["error"] == "invalid_grant"

    def test_description_is_forwarded(self) -> None:
        assert _body(invalid_grant("code expired"))["error_description"] == "code expired"

    def test_no_cache_header(self) -> None:
        assert invalid_grant("x").headers["cache-control"] == "no-store"


# ---------------------------------------------------------------------------
# invalid_scope
# ---------------------------------------------------------------------------


class TestInvalidScope:
    def test_status_code_is_400(self) -> None:
        assert invalid_scope("unknown scope").status_code == 400

    def test_error_code(self) -> None:
        assert _body(invalid_scope("unknown scope"))["error"] == "invalid_scope"

    def test_description_is_forwarded(self) -> None:
        assert _body(invalid_scope("unknown scope"))["error_description"] == "unknown scope"

    def test_no_cache_header(self) -> None:
        assert invalid_scope("x").headers["cache-control"] == "no-store"


# ---------------------------------------------------------------------------
# backend_oauth_error
# ---------------------------------------------------------------------------


class TestBackendOauthError:
    def test_status_code_is_forwarded(self) -> None:
        error_dict = {"error": "access_denied", "error_description": "User denied"}
        assert backend_oauth_error(error_dict, 403).status_code == 403

    def test_body_is_forwarded_verbatim(self) -> None:
        error_dict = {"error": "access_denied", "error_description": "User denied"}
        assert _body(backend_oauth_error(error_dict, 403)) == error_dict

    def test_no_cache_header(self) -> None:
        error_dict = {"error": "access_denied", "error_description": "User denied"}
        assert backend_oauth_error(error_dict, 403).headers["cache-control"] == "no-store"

    def test_custom_status_500(self) -> None:
        error_dict = {"error": "server_error", "error_description": "oops"}
        assert backend_oauth_error(error_dict, 500).status_code == 500

    def test_content_type_is_json(self) -> None:
        error_dict = {"error": "access_denied", "error_description": "denied"}
        response = backend_oauth_error(error_dict, 403)
        assert "application/json" in response.headers["content-type"]


# ---------------------------------------------------------------------------
# OAUTH_NO_CACHE_HEADERS constant
# ---------------------------------------------------------------------------


class TestOauthNoCacheHeaders:
    def test_contains_no_store(self) -> None:
        assert OAUTH_NO_CACHE_HEADERS == {"Cache-Control": "no-store"}

    def test_is_dict(self) -> None:
        assert isinstance(OAUTH_NO_CACHE_HEADERS, dict)

    def test_oauth_error_does_not_mutate_constant(self) -> None:
        """oauth_error copies the headers dict so extra_headers do not mutate the constant."""
        original_value = dict(OAUTH_NO_CACHE_HEADERS)
        oauth_error("slow_down", "too fast", extra_headers={"Retry-After": "5"})
        assert original_value == OAUTH_NO_CACHE_HEADERS


# ---------------------------------------------------------------------------
# Parametrized cross-cutting concerns
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "response_fn, kwargs, expected_status, expected_error",
    [
        (invalid_request, {"description": "bad"}, 400, "invalid_request"),
        (invalid_client, {"description": "unauth"}, 401, "invalid_client"),
        (slow_down, {"description": "slow"}, 400, "slow_down"),
        (rate_limit_exceeded, {"description": "limit"}, 429, "slow_down"),
        (server_error, {"description": "err"}, 500, "server_error"),
        (invalid_grant, {"description": "expired"}, 400, "invalid_grant"),
        (invalid_scope, {"description": "scope"}, 400, "invalid_scope"),
        (unsupported_grant_type, {"description": "nope"}, 400, "unsupported_grant_type"),
        (access_denied, {"description": "denied"}, 400, "access_denied"),
        (invalid_redirect_uri, {"description": "bad uri"}, 400, "invalid_redirect_uri"),
        (authorization_pending, {}, 400, "authorization_pending"),
        (expired_token, {}, 400, "expired_token"),
        (pkce_required, {}, 400, "invalid_request"),
    ],
)
def test_all_constructors_set_no_cache_and_json(
    response_fn: Callable[..., JSONResponse],
    kwargs: dict[str, str | int],
    expected_status: int,
    expected_error: str,
) -> None:
    """Every convenience constructor must include Cache-Control: no-store and JSON content-type."""
    response = response_fn(**kwargs)
    assert response.status_code == expected_status
    assert _body(response)["error"] == expected_error
    assert response.headers["cache-control"] == "no-store"
    assert "application/json" in response.headers["content-type"]
