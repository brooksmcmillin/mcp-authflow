"""Tests for PKCE (RFC 7636) verification and validation helpers."""

import base64
import hashlib

import pytest

from mcp_authflow.pkce import (
    ALLOWED_CODE_CHALLENGE_METHODS,
    validate_code_challenge,
    validate_code_challenge_method,
    validate_code_verifier,
    verify_pkce,
)


def _s256(verifier: str) -> str:
    digest = hashlib.sha256(verifier.encode("utf-8")).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


# A 43-char, valid-charset verifier for use across tests.
VERIFIER = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ"
CHALLENGE_S256 = _s256(VERIFIER)


class TestValidateCodeChallengeMethod:
    @pytest.mark.parametrize("method", ["S256", "plain"])
    def test_allowed_methods(self, method: str) -> None:
        assert validate_code_challenge_method(method) is True

    @pytest.mark.parametrize("method", ["", "s256", "S512", "none", None])
    def test_disallowed_methods(self, method: str | None) -> None:
        assert validate_code_challenge_method(method) is False

    def test_constant_exposes_methods(self) -> None:
        assert frozenset({"S256", "plain"}) == ALLOWED_CODE_CHALLENGE_METHODS


class TestValidateCodeVerifier:
    def test_43_chars_unreserved_is_valid(self) -> None:
        assert validate_code_verifier(VERIFIER) is True

    def test_128_chars_is_valid(self) -> None:
        assert validate_code_verifier("a" * 128) is True

    def test_42_chars_is_invalid(self) -> None:
        assert validate_code_verifier("a" * 42) is False

    def test_129_chars_is_invalid(self) -> None:
        assert validate_code_verifier("a" * 129) is False

    def test_empty_is_invalid(self) -> None:
        assert validate_code_verifier("") is False

    @pytest.mark.parametrize("ch", ["+", "/", "=", " ", "@", "%"])
    def test_reserved_chars_are_invalid(self, ch: str) -> None:
        assert validate_code_verifier(("a" * 42) + ch) is False

    @pytest.mark.parametrize("ch", ["-", ".", "_", "~"])
    def test_unreserved_specials_are_valid(self, ch: str) -> None:
        assert validate_code_verifier(("a" * 42) + ch) is True


class TestValidateCodeChallenge:
    def test_s256_output_is_valid(self) -> None:
        assert validate_code_challenge(CHALLENGE_S256) is True

    def test_43_chars_is_valid(self) -> None:
        assert validate_code_challenge(VERIFIER) is True

    def test_too_short_is_invalid(self) -> None:
        assert validate_code_challenge("a" * 42) is False


class TestVerifyPkce:
    def test_s256_match(self) -> None:
        assert verify_pkce(VERIFIER, CHALLENGE_S256, "S256") is True

    def test_s256_mismatch(self) -> None:
        assert (
            verify_pkce(VERIFIER, _s256("different-verifier-value-here-1234567890123"), "S256")
            is False
        )

    def test_s256_wrong_verifier(self) -> None:
        wrong = "z" * 43
        assert verify_pkce(wrong, CHALLENGE_S256, "S256") is False

    def test_plain_match(self) -> None:
        assert verify_pkce(VERIFIER, VERIFIER, "plain") is True

    def test_plain_mismatch(self) -> None:
        assert verify_pkce(VERIFIER, VERIFIER + "x", "plain") is False

    @pytest.mark.parametrize("method", ["", "s256", "S512", "PLAIN", "none"])
    def test_unknown_method_returns_false(self, method: str) -> None:
        assert verify_pkce(VERIFIER, CHALLENGE_S256, method) is False
