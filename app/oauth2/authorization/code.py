"""Helpers for OAuth2 Authorization Code + PKCE."""

import base64
import hashlib
import hmac
import re
import secrets

from app.oauth2.specs import OAuth2Specs


PKCE_CODE_VERIFIER_PATTERN = re.compile(OAuth2Specs.CODE_VERIFIER_PATTERN)


def create_authorization_code() -> str:
    """Return a new opaque authorization code.

    Returns:
        str: URL-safe random authorization code.
    """
    return secrets.token_urlsafe(OAuth2Specs.AUTHORIZATION_CODE_BYTES)


def hash_authorization_code(
    *,
    code: str,
    secret: str,
) -> str:
    """Return the database lookup digest for an authorization code.

    Args:
        code (str): Raw authorization code sent to the OAuth2 client.
        secret (str): Server-side HMAC secret for code hashing.

    Returns:
        str: Hex-encoded HMAC-SHA-256 digest stored in the database.
    """
    return hmac.new(
        key=secret.encode(),
        msg=code.encode(),
        digestmod=hashlib.sha256,
    ).hexdigest()


def create_s256_code_challenge(
    *,
    code_verifier: str,
) -> str:
    """Return the S256 PKCE challenge for a verifier.

    Args:
        code_verifier (str): PKCE code verifier.

    Returns:
        str: Base64url-encoded SHA-256 digest without padding.
    """
    digest = hashlib.sha256(code_verifier.encode()).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode()


def verify_s256_code_challenge(
    *,
    code_verifier: str,
    code_challenge: str,
) -> bool:
    """Return whether a PKCE verifier matches an S256 challenge.

    Args:
        code_verifier (str): PKCE code verifier submitted at token exchange.
        code_challenge (str): Stored PKCE S256 code challenge.

    Returns:
        bool: True when the verifier is valid for the stored challenge.
    """
    if PKCE_CODE_VERIFIER_PATTERN.fullmatch(code_verifier) is None:
        return False
    return hmac.compare_digest(
        create_s256_code_challenge(code_verifier=code_verifier),
        code_challenge,
    )
