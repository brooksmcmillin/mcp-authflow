"""Tests for shared storage helpers in mcp_authflow.storage.base."""

import hashlib

from mcp_authflow.storage.base import token_fingerprint


def test_fingerprint_is_prefixed_short_hex() -> None:
    fp = token_fingerprint("some-secret-token")
    assert fp.startswith("fp:")
    digest = fp[len("fp:") :]
    assert len(digest) == 8
    assert all(c in "0123456789abcdef" for c in digest)


def test_fingerprint_matches_sha256_truncation() -> None:
    token = "another-token-value"
    expected = "fp:" + hashlib.sha256(token.encode()).hexdigest()[:8]
    assert token_fingerprint(token) == expected


def test_fingerprint_is_deterministic() -> None:
    assert token_fingerprint("repeatable") == token_fingerprint("repeatable")


def test_fingerprint_differs_for_different_tokens() -> None:
    assert token_fingerprint("token-a") != token_fingerprint("token-b")


def test_fingerprint_does_not_leak_token_prefix() -> None:
    # The first 20 chars of the secret must not appear in the fingerprint.
    token = "supersecretvalue1234567890abcdef"
    assert token[:20] not in token_fingerprint(token)
