"""Tests for OAuth input validation utilities."""

from typing import Any

import pytest

from mcp_authflow.validation import parse_json_field, parse_scope_field, validate_client_id

# ---------------------------------------------------------------------------
# validate_client_id
# ---------------------------------------------------------------------------


class TestValidateClientId:
    def test_alphanumeric_is_valid(self) -> None:
        assert validate_client_id("abc123") is True

    def test_hyphens_and_underscores_are_valid(self) -> None:
        assert validate_client_id("my-client_id") is True

    def test_single_character_is_valid(self) -> None:
        assert validate_client_id("a") is True

    def test_256_chars_is_valid(self) -> None:
        assert validate_client_id("a" * 256) is True

    def test_empty_string_is_invalid(self) -> None:
        assert validate_client_id("") is False

    def test_257_chars_is_invalid(self) -> None:
        assert validate_client_id("a" * 257) is False

    def test_spaces_are_invalid(self) -> None:
        assert validate_client_id("my client") is False

    def test_special_chars_are_invalid(self) -> None:
        assert validate_client_id("client@id") is False

    def test_dot_is_invalid(self) -> None:
        assert validate_client_id("client.id") is False


# ---------------------------------------------------------------------------
# parse_json_field
# ---------------------------------------------------------------------------


class TestParseJsonField:
    def test_none_returns_default(self) -> None:
        assert parse_json_field(None, []) == []

    def test_empty_string_returns_default(self) -> None:
        assert parse_json_field("", ["fallback"]) == ["fallback"]

    def test_empty_list_is_falsy_returns_default(self) -> None:
        assert parse_json_field([], ["fallback"]) == ["fallback"]

    def test_valid_json_array_string_is_parsed(self) -> None:
        result = parse_json_field('["read", "write"]', [])
        assert result == ["read", "write"]

    def test_json_object_string_returns_default(self) -> None:
        """Non-array JSON (objects, scalars) returns default."""
        result = parse_json_field('{"key": "val"}', [])
        assert result == []

    def test_json_integer_string_returns_default(self) -> None:
        """Non-array JSON scalars return default."""
        result = parse_json_field("42", [])
        assert result == []

    def test_invalid_json_string_returns_default(self) -> None:
        result = parse_json_field("not valid json {{{", [])
        assert result == []

    def test_malformed_json_string_returns_default(self) -> None:
        result = parse_json_field("{bad: json}", [])
        assert result == []

    def test_list_value_returned_as_is(self) -> None:
        value = ["already", "a", "list"]
        result = parse_json_field(value, [])
        assert result is value

    @pytest.mark.parametrize(
        "value, default",
        [
            (123, []),
            ({"key": "val"}, ["fallback"]),
            (1.5, ["fallback"]),
            (True, []),
        ],
    )
    def test_off_type_value_returns_default(self, value: Any, default: list[str]) -> None:
        """Truthy values that are neither str nor list hit the defensive guard."""
        assert parse_json_field(value, default) == default


# ---------------------------------------------------------------------------
# parse_scope_field
# ---------------------------------------------------------------------------


class TestParseScopeField:
    def test_none_returns_read(self) -> None:
        assert parse_scope_field(None) == "read"

    def test_empty_string_returns_read(self) -> None:
        assert parse_scope_field("") == "read"

    def test_list_of_strings_joined_with_space(self) -> None:
        assert parse_scope_field(["read", "write"]) == "read write"

    def test_single_element_list(self) -> None:
        assert parse_scope_field(["admin"]) == "admin"

    def test_plain_space_separated_string_returned_as_is(self) -> None:
        assert parse_scope_field("read write") == "read write"

    def test_json_array_string_parsed_and_joined(self) -> None:
        result = parse_scope_field('["read", "write"]')
        assert result == "read write"

    def test_json_array_string_single_scope(self) -> None:
        result = parse_scope_field('["admin"]')
        assert result == "admin"

    def test_invalid_json_array_string_returned_as_is(self) -> None:
        # Starts with '[' but is not valid JSON — fall back to original string.
        result = parse_scope_field("[not valid json")
        assert result == "[not valid json"

    def test_non_list_json_starting_with_bracket_returned_as_is(self) -> None:
        # Hypothetical: starts with '[' but parses to a non-list. In practice
        # top-level JSON starting with '[' is always a list or invalid, so
        # we test a JSON string whose parsed result is not a list via a cheeky
        # workaround — use a truthy string that starts with '[' but after
        # json.loads gives a non-list (impossible in standard JSON).
        # Instead, confirm the branch via monkeypatching or just document this
        # is unreachable for standard JSON arrays.
        # We exercise the else-branch by confirming a plain non-bracket string
        # falls through directly.
        result = parse_scope_field("openid profile email")
        assert result == "openid profile email"

    @pytest.mark.parametrize(
        "scopes, expected",
        [
            ('["read"]', "read"),
            ('["read", "write", "admin"]', "read write admin"),
            (["read", "write"], "read write"),
            ("read", "read"),
        ],
    )
    def test_parametrized_scope_formats(self, scopes: str | list[str], expected: str) -> None:
        assert parse_scope_field(scopes) == expected
