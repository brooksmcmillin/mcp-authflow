"""JWT client authentication (private_key_jwt / RFC 7523).

Implements RFC 7523 (JWT Profile for OAuth 2.0 Client Authentication) for
authorization servers. Clients sign a JWT with their private key and submit it
as a ``client_assertion`` at the token endpoint; this module verifies the
assertion against a public key resolved via a pluggable :class:`JWKSProvider`.

Security properties:

- **Algorithm allowlist** — only asymmetric algorithms (RS/ES/PS) are accepted;
  ``none`` and HMAC algorithms are explicitly blocked to prevent algorithm
  confusion.
- **Replay protection** — ``jti`` is required and tracked. With a Redis client
  the cache survives restarts and is shared across processes; without one the
  cache is in-memory with periodic TTL cleanup.
- **Lifetime ceiling** — assertions with ``iat`` more than
  ``JWT_MAX_LIFETIME_SECONDS`` in the past are rejected even if ``exp`` would
  still accept them.
"""

import logging
import math
import threading
import time
from typing import Any, Protocol, cast

import jwt
from jwt.algorithms import AllowedPublicKeys

logger = logging.getLogger(__name__)

JWT_CLIENT_ASSERTION_TYPE = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"

JWT_MAX_CLOCK_SKEW_SECONDS = 60
JWT_MAX_LIFETIME_SECONDS = 300
JWT_REPLAY_CACHE_CLEANUP_INTERVAL = 60

_REDIS_JTI_PREFIX = "mcp_authflow:jti:"

ALLOWED_JWT_ALGORITHMS = {
    "RS256",
    "RS384",
    "RS512",
    "ES256",
    "ES384",
    "ES512",
    "PS256",
    "PS384",
    "PS512",
}

BLOCKED_JWT_ALGORITHMS = {
    "none",
    "HS256",
    "HS384",
    "HS512",
}


class JWTAuthError(Exception):
    """Raised when private_key_jwt client authentication fails."""


class JWKSProvider(Protocol):
    """Resolve a client's JWKS by ``client_id``.

    Implementations choose how to look up the key material — static dict,
    Dynamic Client Registration record, Client ID Metadata Document, etc.
    Returning ``None`` signals "no keys available" and causes authentication
    to fail with :class:`JWTAuthError`.
    """

    async def get_jwks(self, client_id: str) -> dict[str, Any] | None: ...


class AsyncRedisClient(Protocol):
    """Minimal async Redis interface used for JTI replay-cache storage.

    Matches the subset of ``redis.asyncio.Redis`` invoked by this module.
    """

    async def set(
        self,
        name: str,
        value: str | bytes | int,
        *,
        nx: bool = False,
        px: int | None = None,
        **kwargs: Any,  # noqa: ANN401
    ) -> bool | None: ...


class JWTClientAuthenticator:
    """Verify ``private_key_jwt`` client assertions per RFC 7523.

    Args:
        token_endpoint: The token endpoint URL, used as the expected
            ``aud`` claim per RFC 7523 section 3.
        jwks_provider: Resolves the client's JWKS by ``client_id``.
        redis: Optional async Redis client for a persistent / shared JTI
            replay cache. When ``None``, an in-memory cache with periodic
            TTL cleanup is used.
    """

    def __init__(
        self,
        token_endpoint: str,
        jwks_provider: JWKSProvider,
        redis: AsyncRedisClient | None = None,
    ) -> None:
        self.token_endpoint = token_endpoint
        self.jwks_provider = jwks_provider
        self._redis = redis

        self._used_jtis: dict[str, float] = {}
        self._jti_lock = threading.Lock()
        self._last_cleanup = time.time()

    def _cleanup_expired_jtis(self) -> None:
        if self._redis is not None:
            return

        now = time.time()
        if now - self._last_cleanup < JWT_REPLAY_CACHE_CLEANUP_INTERVAL:
            return

        with self._jti_lock:
            if now - self._last_cleanup < JWT_REPLAY_CACHE_CLEANUP_INTERVAL:
                return

            expired_jtis = [jti for jti, exp in self._used_jtis.items() if now > exp]
            for jti in expired_jtis:
                del self._used_jtis[jti]

            if expired_jtis:
                logger.debug("Cleaned up %s expired JTIs from replay cache", len(expired_jtis))

            self._last_cleanup = now

    def _check_and_record_jti(self, jti: str, exp: float) -> bool:
        """Record a JTI in the in-memory cache. Returns False if seen before."""
        self._cleanup_expired_jtis()

        with self._jti_lock:
            if jti in self._used_jtis:
                return False
            self._used_jtis[jti] = exp
            return True

    async def _check_and_record_jti_redis(self, jti: str, exp: float) -> bool:
        """Atomic check-and-record using Redis ``SET NX PX``.

        Safe under concurrent / multi-process deployments.
        """
        now = time.time()
        ttl_seconds = max(0.0, exp - now) + JWT_MAX_CLOCK_SKEW_SECONDS
        ttl_ms = math.ceil(ttl_seconds * 1000)

        key = f"{_REDIS_JTI_PREFIX}{jti}"
        if self._redis is None:
            raise RuntimeError(
                "Redis client is required but was not provided; "
                "_check_and_record_jti_redis must not be called without a Redis client."
            )
        result: bool | None = await self._redis.set(key, "1", nx=True, px=ttl_ms)
        return result is True

    async def authenticate(
        self,
        client_id: str,
        client_assertion: str,
        client_assertion_type: str,
    ) -> bool:
        """Authenticate a client using private_key_jwt.

        Returns ``True`` on success and raises :class:`JWTAuthError` otherwise.
        """
        if client_assertion_type != JWT_CLIENT_ASSERTION_TYPE:
            raise JWTAuthError(
                f"Invalid client_assertion_type: {client_assertion_type}. "
                f"Expected {JWT_CLIENT_ASSERTION_TYPE}"
            )

        if not client_assertion:
            raise JWTAuthError("Missing client_assertion")

        jwks = await self.jwks_provider.get_jwks(client_id)
        if not jwks:
            raise JWTAuthError(f"Could not retrieve JWKS for client {client_id}")

        try:
            await self._verify_jwt(client_id, client_assertion, jwks)
            logger.info("Successfully authenticated client %s via private_key_jwt", client_id)
            return True
        except JWTAuthError:
            raise
        except Exception as e:
            raise JWTAuthError(f"JWT verification failed: {e}") from e

    async def _verify_jwt(
        self,
        client_id: str,
        assertion: str,
        jwks: dict[str, Any],
    ) -> dict[str, Any]:
        try:
            unverified_header = jwt.get_unverified_header(assertion)
        except jwt.exceptions.DecodeError as e:
            raise JWTAuthError(f"Invalid JWT format: {e}") from e

        kid = unverified_header.get("kid")
        alg = unverified_header.get("alg", "RS256")

        if alg in BLOCKED_JWT_ALGORITHMS:
            raise JWTAuthError(f"Algorithm '{alg}' is explicitly blocked for security reasons")

        if alg not in ALLOWED_JWT_ALGORITHMS:
            raise JWTAuthError(
                f"Algorithm '{alg}' is not allowed. "
                f"Allowed algorithms: {sorted(ALLOWED_JWT_ALGORITHMS)}"
            )

        signing_key = self._find_signing_key(jwks, kid, alg)
        if not signing_key:
            raise JWTAuthError(f"No matching key found in JWKS for kid={kid}, alg={alg}")

        now = time.time()

        try:
            payload = jwt.decode(
                assertion,
                signing_key,
                algorithms=[alg],
                audience=self.token_endpoint,
                issuer=client_id,
                options={
                    "require": ["iss", "sub", "aud", "exp", "iat", "jti"],
                    "verify_iss": True,
                    "verify_sub": True,
                    "verify_aud": True,
                    "verify_exp": True,
                    "verify_iat": True,
                },
                leeway=JWT_MAX_CLOCK_SKEW_SECONDS,
            )
        except jwt.ExpiredSignatureError as e:
            raise JWTAuthError("JWT has expired") from e
        except jwt.InvalidAudienceError as e:
            raise JWTAuthError(f"Invalid audience: expected {self.token_endpoint}") from e
        except jwt.InvalidIssuerError as e:
            raise JWTAuthError(f"Invalid issuer: expected {client_id}") from e
        except jwt.DecodeError as e:
            raise JWTAuthError(f"JWT decode error: {e}") from e
        except jwt.InvalidTokenError as e:
            raise JWTAuthError(f"Invalid JWT: {e}") from e

        if payload.get("sub") != client_id:
            raise JWTAuthError(f"Subject mismatch: expected {client_id}, got {payload.get('sub')}")

        iat = payload.get("iat", 0)
        if now - iat > JWT_MAX_LIFETIME_SECONDS + JWT_MAX_CLOCK_SKEW_SECONDS:
            raise JWTAuthError("JWT is too old (iat too far in the past)")

        jti: str = payload["jti"]
        exp = payload.get("exp", now + JWT_MAX_LIFETIME_SECONDS)
        if self._redis is not None:
            accepted = await self._check_and_record_jti_redis(jti, exp)
        else:
            accepted = self._check_and_record_jti(jti, exp)
        if not accepted:
            raise JWTAuthError("JWT replay detected: this token has already been used")

        return payload

    def _find_signing_key(
        self,
        jwks: dict[str, Any],
        kid: str | None,
        alg: str,
    ) -> AllowedPublicKeys | None:
        keys = jwks.get("keys", [])
        if not keys:
            return None

        for key_data in keys:
            if kid and key_data.get("kid") != kid:
                continue

            key_alg = key_data.get("alg")
            if key_alg and key_alg != alg:
                continue

            use = key_data.get("use")
            if use and use != "sig":
                continue

            kty = key_data.get("kty")
            if alg.startswith("RS") and kty != "RSA":
                continue
            if alg.startswith("ES") and kty != "EC":
                continue

            try:
                return self._construct_key(key_data)
            except Exception as e:
                logger.warning("Failed to construct key: %s", e)
                continue

        return None

    def _construct_key(self, key_data: dict[str, Any]) -> AllowedPublicKeys:
        from jwt import PyJWK  # noqa: PLC0415

        jwk = PyJWK.from_dict(key_data)
        return cast(AllowedPublicKeys, jwk.key)
