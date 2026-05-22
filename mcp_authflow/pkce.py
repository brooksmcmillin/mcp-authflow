"""PKCE (RFC 7636) verification and validation helpers.

Authorization-server-side primitives for Proof Key for Code Exchange:

- :func:`verify_pkce` — constant-time check of a ``code_verifier`` against the
  ``code_challenge`` originally bound to the authorization code.
- :func:`validate_code_verifier` / :func:`validate_code_challenge` — input
  sanitization per RFC 7636 §4.1/§4.2 (length 43-128, unreserved charset).
- :func:`validate_code_challenge_method` — method allowlist (``S256``, ``plain``).

Client-side ``code_verifier``/``code_challenge`` generation is intentionally
out of scope for this module; mcp-authflow is an authorization-server
framework.
"""

import base64
import hashlib
import re
import secrets

S256 = "S256"
PLAIN = "plain"

ALLOWED_CODE_CHALLENGE_METHODS: frozenset[str] = frozenset({S256, PLAIN})

# RFC 7636: code_verifier = 43*128 unreserved, where unreserved is
# ALPHA / DIGIT / "-" / "." / "_" / "~". The same charset applies to
# code_challenge (which for S256 is BASE64URL-ENCODE(SHA256(verifier))
# without padding, always 43 chars within the same character set).
_PKCE_CHARSET = re.compile(r"^[A-Za-z0-9._~\-]{43,128}$")


def validate_code_challenge_method(method: str | None) -> bool:
    """Return True if ``method`` is an allowed PKCE method.

    Per RFC 7636 the registered methods are ``plain`` and ``S256``. Servers
    SHOULD reject ``plain`` for public clients; this helper only checks the
    syntactic allowlist — enforcement of S256-only policy is the caller's
    responsibility.
    """
    return method in ALLOWED_CODE_CHALLENGE_METHODS


def validate_code_verifier(code_verifier: str) -> bool:
    """Return True if ``code_verifier`` conforms to RFC 7636 §4.1.

    Length 43-128, characters from the unreserved set
    ``[A-Z] / [a-z] / [0-9] / "-" / "." / "_" / "~"``.
    """
    return bool(_PKCE_CHARSET.match(code_verifier))


def validate_code_challenge(code_challenge: str) -> bool:
    """Return True if ``code_challenge`` conforms to RFC 7636 §4.2.

    Same length/charset rules as the verifier. For S256 challenges the value
    is BASE64URL(SHA256(verifier)) with padding stripped — always 43 chars
    and always within the unreserved set.
    """
    return bool(_PKCE_CHARSET.match(code_challenge))


def verify_pkce(code_verifier: str, code_challenge: str, method: str) -> bool:
    """Verify a PKCE ``code_verifier`` against the stored ``code_challenge``.

    Comparison is constant-time. Returns ``False`` for any unknown method,
    so callers can use this as a single decision point without first checking
    the method allowlist.

    Args:
        code_verifier: The verifier presented at the token endpoint.
        code_challenge: The challenge that was bound to the authorization
            code at the ``/authorize`` step.
        method: ``"S256"`` or ``"plain"``. Any other value returns ``False``.
    """
    if method == S256:
        digest = hashlib.sha256(code_verifier.encode("utf-8")).digest()
        computed = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
        return secrets.compare_digest(computed.encode("utf-8"), code_challenge.encode("utf-8"))
    if method == PLAIN:
        return secrets.compare_digest(code_verifier.encode("utf-8"), code_challenge.encode("utf-8"))
    return False
