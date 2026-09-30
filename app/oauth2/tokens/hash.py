"""HMAC helpers for storing OAuth2 tokens without raw token values."""

import hashlib
import hmac


def hash_oauth2_token(
    *,
    token: str,
    secret: str,
) -> str:
    """Return an indexed HMAC-SHA-256 digest instead of storing a raw token."""
    return hmac.new(
        key=secret.encode("utf-8"),
        msg=token.encode("utf-8"),
        digestmod=hashlib.sha256,
    ).hexdigest()
