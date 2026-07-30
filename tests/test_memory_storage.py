"""Tests for MemoryTokenStorage."""

import time

import pytest

from mcp_authflow.storage.base import hash_token
from mcp_authflow.storage.memory import MemoryTokenStorage


@pytest.fixture
async def storage() -> MemoryTokenStorage:
    """Return an initialized MemoryTokenStorage."""
    s = MemoryTokenStorage()
    await s.initialize()
    return s


# ---------------------------------------------------------------------------
# Lifecycle
# ---------------------------------------------------------------------------


class TestLifecycle:
    async def test_initialize_sets_initialized(self) -> None:
        s = MemoryTokenStorage()
        assert not s._initialized
        await s.initialize()
        assert s._initialized

    async def test_close_clears_tokens_and_resets_flag(self) -> None:
        s = MemoryTokenStorage()
        await s.initialize()
        await s.store_token("tok", "client1", ["read"], int(time.time()) + 3600)
        await s.close()
        assert not s._initialized
        assert s._access_tokens == {}
        assert s._refresh_tokens == {}

    async def test_operations_raise_when_not_initialized(self) -> None:
        s = MemoryTokenStorage()
        with pytest.raises(RuntimeError, match="not initialized"):
            await s.store_token("tok", "c", [], int(time.time()) + 100)
        with pytest.raises(RuntimeError, match="not initialized"):
            await s.load_token("tok")
        with pytest.raises(RuntimeError, match="not initialized"):
            await s.delete_token("tok")
        with pytest.raises(RuntimeError, match="not initialized"):
            await s.cleanup_expired_tokens()
        with pytest.raises(RuntimeError, match="not initialized"):
            await s.get_token_count()
        with pytest.raises(RuntimeError, match="not initialized"):
            await s.store_refresh_token("rt", "c", [], int(time.time()) + 100)
        with pytest.raises(RuntimeError, match="not initialized"):
            await s.load_refresh_token("rt")
        with pytest.raises(RuntimeError, match="not initialized"):
            await s.delete_refresh_token("rt")
        with pytest.raises(RuntimeError, match="not initialized"):
            await s.cleanup_expired_refresh_tokens()
        with pytest.raises(RuntimeError, match="not initialized"):
            await s.get_refresh_token_count()


# ---------------------------------------------------------------------------
# Access token CRUD
# ---------------------------------------------------------------------------


class TestStoreAndLoadToken:
    async def test_store_and_load_basic(self, storage: MemoryTokenStorage) -> None:
        expires_at = int(time.time()) + 3600
        await storage.store_token("tok1", "client1", ["read", "write"], expires_at)
        data = await storage.load_token("tok1")
        assert data is not None
        assert data["token"] == "tok1"
        assert data["client_id"] == "client1"
        assert data["scopes"] == ["read", "write"]
        assert data["expires_at"] == expires_at
        assert data["resource"] is None
        assert data["user_id"] is None

    async def test_store_with_resource_and_user(self, storage: MemoryTokenStorage) -> None:
        expires_at = int(time.time()) + 3600
        await storage.store_token(
            "tok2", "client2", ["admin"], expires_at, resource="https://api.example.com", user_id=42
        )
        data = await storage.load_token("tok2")
        assert data is not None
        assert data["resource"] == "https://api.example.com"
        assert data["user_id"] == 42

    async def test_string_user_id_round_trips(self, storage: MemoryTokenStorage) -> None:
        """user_id is stored verbatim so UUID/TEXT user keys work, not just INTEGER ones."""
        expires_at = int(time.time()) + 3600
        user_id = "5f7c9d3e-1b2a-4c6d-8e9f-0a1b2c3d4e5f"
        await storage.store_token("tok-uuid", "c", ["read"], expires_at, user_id=user_id)
        await storage.store_refresh_token("rt-uuid", "c", ["read"], expires_at, user_id=user_id)

        access = await storage.load_token("tok-uuid")
        refresh = await storage.load_refresh_token("rt-uuid")
        assert access is not None
        assert refresh is not None
        assert access["user_id"] == user_id
        assert refresh["user_id"] == user_id

    async def test_load_returns_copy(self, storage: MemoryTokenStorage) -> None:
        """Returned dict is a shallow copy — replacing a top-level key does not affect storage."""
        expires_at = int(time.time()) + 3600
        await storage.store_token("tok3", "c", ["read"], expires_at)
        data = await storage.load_token("tok3")
        assert data is not None
        # Replace a top-level key — storage should be unaffected
        data["client_id"] = "tampered"
        data2 = await storage.load_token("tok3")
        assert data2 is not None
        assert data2["client_id"] == "c"

    async def test_scopes_are_copied_on_store(self, storage: MemoryTokenStorage) -> None:
        """Mutating the original scopes list must not affect stored data."""
        scopes = ["read"]
        expires_at = int(time.time()) + 3600
        await storage.store_token("tok4", "c", scopes, expires_at)
        scopes.append("write")
        data = await storage.load_token("tok4")
        assert data is not None
        assert data["scopes"] == ["read"]

    async def test_load_nonexistent_returns_none(self, storage: MemoryTokenStorage) -> None:
        result = await storage.load_token("nonexistent")
        assert result is None

    async def test_load_expired_returns_none_and_deletes(self, storage: MemoryTokenStorage) -> None:
        # Store a token that is already expired
        expires_at = int(time.time()) - 1
        await storage.store_token("expired_tok", "c", ["read"], expires_at)
        result = await storage.load_token("expired_tok")
        assert result is None
        # Expired token should have been removed from internal dict
        assert hash_token("expired_tok") not in storage._access_tokens


class TestTokenHashedAtRest:
    """Verify tokens are keyed by digest, mirroring the PostgreSQL backend."""

    async def test_access_token_keyed_by_digest(self, storage: MemoryTokenStorage) -> None:
        await storage.store_token("secret-access", "c", ["read"], int(time.time()) + 3600)
        assert "secret-access" not in storage._access_tokens
        assert hash_token("secret-access") in storage._access_tokens

    async def test_refresh_token_keyed_by_digest(self, storage: MemoryTokenStorage) -> None:
        await storage.store_refresh_token("secret-refresh", "c", ["read"], int(time.time()) + 3600)
        assert "secret-refresh" not in storage._refresh_tokens
        assert hash_token("secret-refresh") in storage._refresh_tokens


class TestDeleteToken:
    async def test_delete_existing_token(self, storage: MemoryTokenStorage) -> None:
        await storage.store_token("tok", "c", [], int(time.time()) + 100)
        await storage.delete_token("tok")
        assert await storage.load_token("tok") is None

    async def test_delete_nonexistent_token_is_noop(self, storage: MemoryTokenStorage) -> None:
        # Must not raise
        await storage.delete_token("does-not-exist")


class TestCleanupExpiredTokens:
    async def test_returns_zero_when_no_tokens(self, storage: MemoryTokenStorage) -> None:
        count = await storage.cleanup_expired_tokens()
        assert count == 0

    async def test_removes_only_expired_tokens(self, storage: MemoryTokenStorage) -> None:
        now = int(time.time())
        await storage.store_token("valid", "c", [], now + 3600)
        await storage.store_token("expired1", "c", [], now - 1)
        await storage.store_token("expired2", "c", [], now - 100)

        count = await storage.cleanup_expired_tokens()
        assert count == 2
        assert await storage.load_token("valid") is not None
        assert hash_token("expired1") not in storage._access_tokens
        assert hash_token("expired2") not in storage._access_tokens

    async def test_returns_zero_when_all_valid(self, storage: MemoryTokenStorage) -> None:
        now = int(time.time())
        await storage.store_token("tok1", "c", [], now + 3600)
        await storage.store_token("tok2", "c", [], now + 7200)
        count = await storage.cleanup_expired_tokens()
        assert count == 0


class TestGetTokenCount:
    async def test_count_reflects_stored_tokens(self, storage: MemoryTokenStorage) -> None:
        assert await storage.get_token_count() == 0
        await storage.store_token("t1", "c", [], int(time.time()) + 100)
        assert await storage.get_token_count() == 1
        await storage.store_token("t2", "c", [], int(time.time()) + 100)
        assert await storage.get_token_count() == 2
        await storage.delete_token("t1")
        assert await storage.get_token_count() == 1


# ---------------------------------------------------------------------------
# Refresh token CRUD
# ---------------------------------------------------------------------------


class TestStoreAndLoadRefreshToken:
    async def test_store_and_load_basic(self, storage: MemoryTokenStorage) -> None:
        expires_at = int(time.time()) + 86400
        await storage.store_refresh_token("rt1", "client1", ["read"], expires_at)
        data = await storage.load_refresh_token("rt1")
        assert data is not None
        assert data["token"] == "rt1"
        assert data["client_id"] == "client1"
        assert data["scopes"] == ["read"]
        assert data["resource"] is None
        assert data["user_id"] is None

    async def test_store_with_resource_and_user(self, storage: MemoryTokenStorage) -> None:
        expires_at = int(time.time()) + 86400
        await storage.store_refresh_token(
            "rt2", "c", ["write"], expires_at, resource="https://res", user_id=7
        )
        data = await storage.load_refresh_token("rt2")
        assert data is not None
        assert data["resource"] == "https://res"
        assert data["user_id"] == 7

    async def test_load_nonexistent_returns_none(self, storage: MemoryTokenStorage) -> None:
        assert await storage.load_refresh_token("no-such-token") is None

    async def test_load_expired_returns_none_and_deletes(self, storage: MemoryTokenStorage) -> None:
        expires_at = int(time.time()) - 1
        await storage.store_refresh_token("expired_rt", "c", [], expires_at)
        result = await storage.load_refresh_token("expired_rt")
        assert result is None
        assert hash_token("expired_rt") not in storage._refresh_tokens

    async def test_load_returns_copy(self, storage: MemoryTokenStorage) -> None:
        """Returned dict is a shallow copy — replacing a top-level key does not affect storage."""
        expires_at = int(time.time()) + 86400
        await storage.store_refresh_token("rt3", "c", ["read"], expires_at)
        data = await storage.load_refresh_token("rt3")
        assert data is not None
        # Replace a top-level key — storage should be unaffected
        data["client_id"] = "tampered"
        data2 = await storage.load_refresh_token("rt3")
        assert data2 is not None
        assert data2["client_id"] == "c"


class TestDeleteRefreshToken:
    async def test_delete_existing(self, storage: MemoryTokenStorage) -> None:
        await storage.store_refresh_token("rt", "c", [], int(time.time()) + 100)
        await storage.delete_refresh_token("rt")
        assert await storage.load_refresh_token("rt") is None

    async def test_delete_nonexistent_is_noop(self, storage: MemoryTokenStorage) -> None:
        await storage.delete_refresh_token("no-such-rt")


class TestRevokeClientTokens:
    async def test_removes_both_token_types_for_only_the_requested_client(
        self, storage: MemoryTokenStorage
    ) -> None:
        expires_at = int(time.time()) + 3600
        await storage.store_token("access-a", "client-a", [], expires_at)
        await storage.store_refresh_token("refresh-a", "client-a", [], expires_at)
        await storage.store_token("access-b", "client-b", [], expires_at)
        await storage.store_refresh_token("refresh-b", "client-b", [], expires_at)

        count = await storage.revoke_client_tokens("client-a")

        assert count == 2
        assert await storage.load_token("access-a") is None
        assert await storage.load_refresh_token("refresh-a") is None
        assert await storage.load_token("access-b") is not None
        assert await storage.load_refresh_token("refresh-b") is not None

    async def test_unknown_client_is_noop(self, storage: MemoryTokenStorage) -> None:
        assert await storage.revoke_client_tokens("unknown") == 0


class TestCleanupExpiredRefreshTokens:
    async def test_returns_zero_when_empty(self, storage: MemoryTokenStorage) -> None:
        assert await storage.cleanup_expired_refresh_tokens() == 0

    async def test_removes_only_expired(self, storage: MemoryTokenStorage) -> None:
        now = int(time.time())
        await storage.store_refresh_token("valid_rt", "c", [], now + 86400)
        await storage.store_refresh_token("exp_rt1", "c", [], now - 1)
        await storage.store_refresh_token("exp_rt2", "c", [], now - 500)

        count = await storage.cleanup_expired_refresh_tokens()
        assert count == 2
        assert await storage.load_refresh_token("valid_rt") is not None
        assert hash_token("exp_rt1") not in storage._refresh_tokens
        assert hash_token("exp_rt2") not in storage._refresh_tokens

    async def test_returns_zero_when_all_valid(self, storage: MemoryTokenStorage) -> None:
        now = int(time.time())
        await storage.store_refresh_token("rt1", "c", [], now + 100)
        await storage.store_refresh_token("rt2", "c", [], now + 200)
        assert await storage.cleanup_expired_refresh_tokens() == 0


class TestGetRefreshTokenCount:
    async def test_count_reflects_stored_refresh_tokens(self, storage: MemoryTokenStorage) -> None:
        assert await storage.get_refresh_token_count() == 0
        await storage.store_refresh_token("rt1", "c", [], int(time.time()) + 100)
        assert await storage.get_refresh_token_count() == 1
        await storage.store_refresh_token("rt2", "c", [], int(time.time()) + 100)
        assert await storage.get_refresh_token_count() == 2
        await storage.delete_refresh_token("rt1")
        assert await storage.get_refresh_token_count() == 1
