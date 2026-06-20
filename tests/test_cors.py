"""Tests for CORS origin validation."""

from unittest.mock import patch

from starlette.requests import Request

from mcp_authflow.cors import (
    build_cors_headers,
    get_cors_origin,
    parse_allowed_origins,
)


def _make_request(origin: str | None = None) -> Request:
    """Create a Starlette Request with an optional Origin header."""
    headers: dict[str, str] = {}
    if origin is not None:
        headers["origin"] = origin

    async def receive():  # type: ignore[no-untyped-def]
        return {"type": "http.request", "body": b""}

    scope = {
        "type": "http",
        "method": "GET",
        "path": "/",
        "headers": [(k.encode(), v.encode()) for k, v in headers.items()],
    }
    return Request(scope, receive)


# --- parse_allowed_origins ---


class TestParseAllowedOrigins:
    def test_empty_env(self) -> None:
        with patch.dict("os.environ", {}, clear=True):
            assert parse_allowed_origins("ALLOWED_MCP_ORIGINS") == []

    def test_unset_env(self) -> None:
        with patch.dict("os.environ", {}, clear=True):
            assert parse_allowed_origins("NONEXISTENT_VAR") == []

    def test_single_origin(self) -> None:
        with patch.dict("os.environ", {"ALLOWED_MCP_ORIGINS": "https://example.com"}):
            assert parse_allowed_origins() == ["https://example.com"]

    def test_multiple_origins(self) -> None:
        val = "https://a.com,https://b.com,https://c.com"
        with patch.dict("os.environ", {"ALLOWED_MCP_ORIGINS": val}):
            result = parse_allowed_origins()
            assert result == ["https://a.com", "https://b.com", "https://c.com"]

    def test_whitespace_stripped(self) -> None:
        val = " https://a.com , https://b.com "
        with patch.dict("os.environ", {"ALLOWED_MCP_ORIGINS": val}):
            result = parse_allowed_origins()
            assert result == ["https://a.com", "https://b.com"]

    def test_empty_entries_skipped(self) -> None:
        val = "https://a.com,,, ,https://b.com"
        with patch.dict("os.environ", {"ALLOWED_MCP_ORIGINS": val}):
            result = parse_allowed_origins()
            assert result == ["https://a.com", "https://b.com"]

    def test_custom_env_var(self) -> None:
        with patch.dict("os.environ", {"MY_ORIGINS": "https://custom.com"}):
            assert parse_allowed_origins("MY_ORIGINS") == ["https://custom.com"]


# --- get_cors_origin ---


class TestGetCorsOrigin:
    def test_allowed_origin_returned(self) -> None:
        request = _make_request("https://allowed.com")
        result = get_cors_origin(request, ["https://allowed.com"])
        assert result == "https://allowed.com"

    def test_disallowed_origin_returns_empty(self) -> None:
        request = _make_request("https://evil.com")
        result = get_cors_origin(request, ["https://allowed.com"])
        assert result == ""

    def test_no_origin_header_returns_empty(self) -> None:
        request = _make_request()
        result = get_cors_origin(request, ["https://allowed.com"])
        assert result == ""

    def test_empty_allowlist(self) -> None:
        request = _make_request("https://any.com")
        result = get_cors_origin(request, [])
        assert result == ""

    def test_multiple_allowed_origins(self) -> None:
        allowed = ["https://a.com", "https://b.com", "https://c.com"]
        request = _make_request("https://b.com")
        assert get_cors_origin(request, allowed) == "https://b.com"


# --- build_cors_headers ---


class TestBuildCorsHeaders:
    def test_allowed_origin_includes_acao(self) -> None:
        request = _make_request("https://allowed.com")
        headers = build_cors_headers(request, ["https://allowed.com"])
        assert headers["Access-Control-Allow-Origin"] == "https://allowed.com"
        assert headers["Access-Control-Allow-Methods"] == "GET, OPTIONS"
        assert headers["Access-Control-Allow-Headers"] == "Authorization, Content-Type, Accept"
        assert headers["Vary"] == "Origin"

    def test_disallowed_origin_omits_acao(self) -> None:
        request = _make_request("https://evil.com")
        headers = build_cors_headers(request, ["https://allowed.com"])
        assert "Access-Control-Allow-Origin" not in headers
        assert headers["Access-Control-Allow-Methods"] == "GET, OPTIONS"
        assert headers["Access-Control-Allow-Headers"] == "Authorization, Content-Type, Accept"
        assert headers["Vary"] == "Origin"

    def test_no_origin_header_omits_acao(self) -> None:
        request = _make_request()
        headers = build_cors_headers(request, ["https://allowed.com"])
        assert "Access-Control-Allow-Origin" not in headers

    def test_always_includes_methods_and_headers(self) -> None:
        request = _make_request("https://evil.com")
        headers = build_cors_headers(request, [])
        assert "Access-Control-Allow-Methods" in headers
        assert "Access-Control-Allow-Headers" in headers
        assert headers["Vary"] == "Origin"
        assert len(headers) == 3  # methods + headers + Vary, no ACAO
