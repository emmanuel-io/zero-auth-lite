"""Helpers for OAuth2 Authorization Code + PKCE."""

import base64
import hashlib
import hmac
import re
import secrets

from app.oauth2.specs import OAuth2Specs


PKCE_CODE_VERIFIER_PATTERN = re.compile(OAuth2Specs.CODE_VERIFIER_PATTERN)


def create_authorization_code() -> str:
    """Return a new opaque, URL-safe authorization code."""
    return secrets.token_urlsafe(OAuth2Specs.AUTHORIZATION_CODE_BYTES)


def hash_authorization_code(
    *,
    code: str,
    secret: str,
) -> str:
    """Return an HMAC-SHA-256 lookup digest instead of storing the raw code."""
    return hmac.new(
        key=secret.encode(),
        msg=code.encode(),
        digestmod=hashlib.sha256,
    ).hexdigest()


def create_s256_code_challenge(
    *,
    code_verifier: str,
) -> str:
    """Return the unpadded Base64url S256 PKCE challenge for a verifier."""
    digest = hashlib.sha256(code_verifier.encode()).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode()


def verify_s256_code_challenge(
    *,
    code_verifier: str,
    code_challenge: str,
) -> bool:
    """Validate an S256 PKCE verifier with a constant-time comparison."""
    if PKCE_CODE_VERIFIER_PATTERN.fullmatch(code_verifier) is None:
        return False
    return hmac.compare_digest(
        create_s256_code_challenge(code_verifier=code_verifier),
        code_challenge,
    )
