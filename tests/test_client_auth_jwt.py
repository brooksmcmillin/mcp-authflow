"""Tests for private_key_jwt client authentication (RFC 7523)."""

import time
from typing import Any, cast

import fakeredis.aioredis  # pyright: ignore[reportMissingImports]
import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from mcp_authflow.client_auth import (
    ALLOWED_JWT_ALGORITHMS,
    BLOCKED_JWT_ALGORITHMS,
    JWT_CLIENT_ASSERTION_TYPE,
    AsyncRedisClient,
    JWKSProvider,
    JWTAuthError,
    JWTClientAuthenticator,
)


class _StaticJWKSProvider:
    """Test JWKSProvider that returns a single preconfigured JWKS."""

    def __init__(self, jwks: dict[str, Any] | None = None) -> None:
        self.jwks = jwks
        self.calls: list[str] = []

    async def get_jwks(self, client_id: str) -> dict[str, Any] | None:
        self.calls.append(client_id)
        return self.jwks


def _generate_rsa_keypair() -> tuple[rsa.RSAPrivateKey, rsa.RSAPublicKey]:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return private_key, private_key.public_key()


def _make_jwks_from_public_key(public_key: Any, kid: str = "test-key-1") -> dict[str, Any]:
    from jwt.algorithms import RSAAlgorithm

    jwk = RSAAlgorithm.to_jwk(public_key, as_dict=True)
    jwk["kid"] = kid
    jwk["use"] = "sig"
    jwk["alg"] = "RS256"
    return {"keys": [jwk]}


def _sign_jwt(
    private_key: Any,
    client_id: str = "https://client.example.com",
    audience: str = "https://auth.example.com/token",
    kid: str = "test-key-1",
    algorithm: str = "RS256",
    extra_claims: dict[str, Any] | None = None,
    iat_offset: int = 0,
    exp_offset: int = 300,
) -> str:
    now = int(time.time())
    payload: dict[str, Any] = {
        "iss": client_id,
        "sub": client_id,
        "aud": audience,
        "iat": now + iat_offset,
        "exp": now + exp_offset,
        "jti": f"test-jti-{now}",
    }
    if extra_claims:
        payload.update(extra_claims)
    return jwt.encode(
        payload, private_key, algorithm=algorithm, headers={"kid": kid, "alg": algorithm}
    )


def _create_authenticator(
    *,
    jwks: dict[str, Any] | None = None,
    token_endpoint: str = "https://auth.example.com/token",
    redis: AsyncRedisClient | None = None,
) -> tuple[JWTClientAuthenticator, _StaticJWKSProvider]:
    provider = _StaticJWKSProvider(jwks)
    auth = JWTClientAuthenticator(
        token_endpoint=token_endpoint,
        jwks_provider=cast(JWKSProvider, provider),
        redis=redis,
    )
    return auth, provider


class TestAlgorithmWhitelist:
    def test_allowed_algorithms_are_asymmetric(self) -> None:
        for alg in ALLOWED_JWT_ALGORITHMS:
            assert alg.startswith(("RS", "ES", "PS"))

    def test_blocked_algorithms_include_symmetric(self) -> None:
        assert "none" in BLOCKED_JWT_ALGORITHMS
        for alg in ("HS256", "HS384", "HS512"):
            assert alg in BLOCKED_JWT_ALGORITHMS

    def test_no_overlap_between_allowed_and_blocked(self) -> None:
        assert ALLOWED_JWT_ALGORITHMS.isdisjoint(BLOCKED_JWT_ALGORITHMS)


class TestJTIReplayProtection:
    def test_new_jti_is_accepted(self) -> None:
        auth, _ = _create_authenticator()
        assert auth._check_and_record_jti("jti-1", time.time() + 300) is True

    def test_duplicate_jti_is_rejected(self) -> None:
        auth, _ = _create_authenticator()
        exp = time.time() + 300
        auth._check_and_record_jti("jti-dup", exp)
        assert auth._check_and_record_jti("jti-dup", exp) is False

    def test_expired_jtis_are_cleaned_up(self) -> None:
        auth, _ = _create_authenticator()
        auth._used_jtis["old-jti"] = time.time() - 100
        auth._last_cleanup = 0

        auth._cleanup_expired_jtis()
        assert "old-jti" not in auth._used_jtis


class TestRedisJTIReplayProtection:
    @pytest.fixture
    def fake_redis(self) -> fakeredis.aioredis.FakeRedis:
        return fakeredis.aioredis.FakeRedis()

    @pytest.mark.asyncio
    async def test_new_jti_accepted_via_redis(self, fake_redis: Any) -> None:
        auth, _ = _create_authenticator(redis=cast(AsyncRedisClient, fake_redis))
        assert await auth._check_and_record_jti_redis("jti-new", time.time() + 300) is True

    @pytest.mark.asyncio
    async def test_duplicate_jti_rejected_via_redis(self, fake_redis: Any) -> None:
        auth, _ = _create_authenticator(redis=cast(AsyncRedisClient, fake_redis))
        exp = time.time() + 300
        assert await auth._check_and_record_jti_redis("jti-dup", exp) is True
        assert await auth._check_and_record_jti_redis("jti-dup", exp) is False

    @pytest.mark.asyncio
    async def test_redis_jti_key_has_ttl(self, fake_redis: Any) -> None:
        auth, _ = _create_authenticator(redis=cast(AsyncRedisClient, fake_redis))
        await auth._check_and_record_jti_redis("ttl-jti", time.time() + 300)
        ttl = await fake_redis.pttl("mcp_authflow:jti:ttl-jti")
        assert ttl > 0

    @pytest.mark.asyncio
    async def test_cross_instance_replay_detected_via_redis(self, fake_redis: Any) -> None:
        redis = cast(AsyncRedisClient, fake_redis)
        auth1, _ = _create_authenticator(redis=redis)
        auth2, _ = _create_authenticator(redis=redis)
        exp = time.time() + 300
        assert await auth1._check_and_record_jti_redis("shared", exp) is True
        assert await auth2._check_and_record_jti_redis("shared", exp) is False

    @pytest.mark.asyncio
    async def test_verify_jwt_uses_redis_when_available(self, fake_redis: Any) -> None:
        private_key, public_key = _generate_rsa_keypair()
        jwks = _make_jwks_from_public_key(public_key)
        auth, _ = _create_authenticator(jwks=jwks, redis=cast(AsyncRedisClient, fake_redis))

        client_id = "https://client.example.com"
        now = int(time.time())
        assertion = jwt.encode(
            {
                "iss": client_id,
                "sub": client_id,
                "aud": auth.token_endpoint,
                "iat": now,
                "exp": now + 300,
                "jti": "redis-replay-test-jti",
            },
            private_key,
            algorithm="RS256",
            headers={"kid": "test-key-1"},
        )

        assert await auth._verify_jwt(client_id, assertion, jwks) is not None
        with pytest.raises(JWTAuthError, match="replay"):
            await auth._verify_jwt(client_id, assertion, jwks)

    @pytest.mark.asyncio
    async def test_cleanup_is_noop_when_redis_configured(self, fake_redis: Any) -> None:
        auth, _ = _create_authenticator(redis=cast(AsyncRedisClient, fake_redis))
        auth._used_jtis["should-stay"] = time.time() - 100
        auth._last_cleanup = 0
        auth._cleanup_expired_jtis()
        assert "should-stay" in auth._used_jtis


class TestAuthenticate:
    @pytest.mark.asyncio
    async def test_invalid_assertion_type_raises(self) -> None:
        auth, _ = _create_authenticator()
        with pytest.raises(JWTAuthError, match="Invalid client_assertion_type"):
            await auth.authenticate(
                client_id="test",
                client_assertion="some-jwt",
                client_assertion_type="wrong-type",
            )

    @pytest.mark.asyncio
    async def test_missing_assertion_raises(self) -> None:
        auth, _ = _create_authenticator()
        with pytest.raises(JWTAuthError, match="Missing client_assertion"):
            await auth.authenticate(
                client_id="test",
                client_assertion="",
                client_assertion_type=JWT_CLIENT_ASSERTION_TYPE,
            )

    @pytest.mark.asyncio
    async def test_missing_jwks_raises(self) -> None:
        auth, provider = _create_authenticator(jwks=None)
        with pytest.raises(JWTAuthError, match="Could not retrieve JWKS"):
            await auth.authenticate(
                client_id="https://client.example.com",
                client_assertion="some.jwt.here",
                client_assertion_type=JWT_CLIENT_ASSERTION_TYPE,
            )
        assert provider.calls == ["https://client.example.com"]

    @pytest.mark.asyncio
    async def test_successful_authentication(self) -> None:
        private_key, public_key = _generate_rsa_keypair()
        jwks = _make_jwks_from_public_key(public_key)
        auth, _ = _create_authenticator(jwks=jwks)

        client_id = "https://client.example.com"
        assertion = _sign_jwt(private_key, client_id=client_id)

        assert (
            await auth.authenticate(
                client_id=client_id,
                client_assertion=assertion,
                client_assertion_type=JWT_CLIENT_ASSERTION_TYPE,
            )
            is True
        )


class TestVerifyJWT:
    @pytest.mark.asyncio
    async def test_blocked_algorithm_rejected(self) -> None:
        auth, _ = _create_authenticator()
        payload = {
            "iss": "client",
            "sub": "client",
            "aud": auth.token_endpoint,
            "iat": int(time.time()),
            "exp": int(time.time()) + 300,
        }
        token = jwt.encode(payload, "secret", algorithm="HS256")
        with pytest.raises(JWTAuthError, match="explicitly blocked"):
            await auth._verify_jwt("client", token, {"keys": []})

    @pytest.mark.asyncio
    async def test_unknown_algorithm_rejected(self) -> None:
        import base64
        import json

        auth, _ = _create_authenticator()
        header = base64.urlsafe_b64encode(
            json.dumps({"alg": "XX999", "typ": "JWT"}).encode()
        ).rstrip(b"=")
        payload_part = base64.urlsafe_b64encode(json.dumps({"iss": "x"}).encode()).rstrip(b"=")
        fake_token = f"{header.decode()}.{payload_part.decode()}.fake-sig"

        with pytest.raises(JWTAuthError, match="not allowed"):
            await auth._verify_jwt("client", fake_token, {"keys": []})

    @pytest.mark.asyncio
    async def test_expired_jwt_rejected(self) -> None:
        private_key, public_key = _generate_rsa_keypair()
        jwks = _make_jwks_from_public_key(public_key)
        auth, _ = _create_authenticator(jwks=jwks)

        assertion = _sign_jwt(
            private_key,
            audience=auth.token_endpoint,
            exp_offset=-600,
            iat_offset=-900,
        )
        with pytest.raises(JWTAuthError, match="expired"):
            await auth._verify_jwt("https://client.example.com", assertion, jwks)

    @pytest.mark.asyncio
    async def test_wrong_audience_rejected(self) -> None:
        private_key, public_key = _generate_rsa_keypair()
        jwks = _make_jwks_from_public_key(public_key)
        auth, _ = _create_authenticator(jwks=jwks)

        assertion = _sign_jwt(private_key, audience="https://wrong.example.com/token")
        with pytest.raises(JWTAuthError, match="audience"):
            await auth._verify_jwt("https://client.example.com", assertion, jwks)

    @pytest.mark.asyncio
    async def test_wrong_issuer_rejected(self) -> None:
        private_key, public_key = _generate_rsa_keypair()
        jwks = _make_jwks_from_public_key(public_key)
        auth, _ = _create_authenticator(jwks=jwks)

        assertion = _sign_jwt(
            private_key,
            client_id="https://wrong-issuer.example.com",
            audience=auth.token_endpoint,
        )
        with pytest.raises(JWTAuthError, match="issuer"):
            await auth._verify_jwt("https://correct.example.com", assertion, jwks)

    @pytest.mark.asyncio
    async def test_subject_mismatch_rejected(self) -> None:
        private_key, public_key = _generate_rsa_keypair()
        jwks = _make_jwks_from_public_key(public_key)
        auth, _ = _create_authenticator(jwks=jwks)

        client_id = "https://client.example.com"
        assertion = _sign_jwt(
            private_key,
            client_id=client_id,
            audience=auth.token_endpoint,
            extra_claims={"sub": "https://different.example.com"},
        )
        with pytest.raises(JWTAuthError, match="Subject mismatch"):
            await auth._verify_jwt(client_id, assertion, jwks)

    @pytest.mark.asyncio
    async def test_too_old_jwt_rejected(self) -> None:
        private_key, public_key = _generate_rsa_keypair()
        jwks = _make_jwks_from_public_key(public_key)
        auth, _ = _create_authenticator(jwks=jwks)

        client_id = "https://client.example.com"
        assertion = _sign_jwt(
            private_key,
            client_id=client_id,
            audience=auth.token_endpoint,
            iat_offset=-700,
            exp_offset=300,
        )
        with pytest.raises(JWTAuthError, match="too old"):
            await auth._verify_jwt(client_id, assertion, jwks)

    @pytest.mark.asyncio
    async def test_missing_jti_rejected(self) -> None:
        private_key, public_key = _generate_rsa_keypair()
        jwks = _make_jwks_from_public_key(public_key)
        auth, _ = _create_authenticator(jwks=jwks)

        client_id = "https://client.example.com"
        now = int(time.time())
        assertion = jwt.encode(
            {
                "iss": client_id,
                "sub": client_id,
                "aud": auth.token_endpoint,
                "iat": now,
                "exp": now + 300,
            },
            private_key,
            algorithm="RS256",
            headers={"kid": "test-key-1"},
        )
        with pytest.raises(JWTAuthError, match="jti"):
            await auth._verify_jwt(client_id, assertion, jwks)

    @pytest.mark.asyncio
    async def test_jti_replay_rejected(self) -> None:
        private_key, public_key = _generate_rsa_keypair()
        jwks = _make_jwks_from_public_key(public_key)
        auth, _ = _create_authenticator(jwks=jwks)

        client_id = "https://client.example.com"
        now = int(time.time())
        assertion = jwt.encode(
            {
                "iss": client_id,
                "sub": client_id,
                "aud": auth.token_endpoint,
                "iat": now,
                "exp": now + 300,
                "jti": "replay-test-jti",
            },
            private_key,
            algorithm="RS256",
            headers={"kid": "test-key-1"},
        )

        assert await auth._verify_jwt(client_id, assertion, jwks) is not None
        with pytest.raises(JWTAuthError, match="replay"):
            await auth._verify_jwt(client_id, assertion, jwks)

    @pytest.mark.asyncio
    async def test_valid_jwt_returns_payload(self) -> None:
        private_key, public_key = _generate_rsa_keypair()
        jwks = _make_jwks_from_public_key(public_key)
        auth, _ = _create_authenticator(jwks=jwks)

        client_id = "https://client.example.com"
        assertion = _sign_jwt(private_key, client_id=client_id, audience=auth.token_endpoint)

        result = await auth._verify_jwt(client_id, assertion, jwks)
        assert result["iss"] == client_id
        assert result["sub"] == client_id
        assert result["aud"] == auth.token_endpoint


class TestFindSigningKey:
    def test_matching_key_found(self) -> None:
        _, public_key = _generate_rsa_keypair()
        jwks = _make_jwks_from_public_key(public_key, kid="my-key")
        auth, _ = _create_authenticator(jwks=jwks)

        assert auth._find_signing_key(jwks, kid="my-key", alg="RS256") is not None

    def test_wrong_kid_returns_none(self) -> None:
        _, public_key = _generate_rsa_keypair()
        jwks = _make_jwks_from_public_key(public_key, kid="key-1")
        auth, _ = _create_authenticator(jwks=jwks)

        assert auth._find_signing_key(jwks, kid="key-2", alg="RS256") is None

    def test_wrong_algorithm_returns_none(self) -> None:
        _, public_key = _generate_rsa_keypair()
        jwks = _make_jwks_from_public_key(public_key, kid="key-1")
        auth, _ = _create_authenticator(jwks=jwks)

        assert auth._find_signing_key(jwks, kid="key-1", alg="ES256") is None

    def test_empty_jwks_returns_none(self) -> None:
        auth, _ = _create_authenticator()
        assert auth._find_signing_key({"keys": []}, kid="any", alg="RS256") is None

    def test_key_with_wrong_use_skipped(self) -> None:
        _, public_key = _generate_rsa_keypair()
        jwks = _make_jwks_from_public_key(public_key, kid="enc-key")
        jwks["keys"][0]["use"] = "enc"
        auth, _ = _create_authenticator(jwks=jwks)

        assert auth._find_signing_key(jwks, kid="enc-key", alg="RS256") is None
