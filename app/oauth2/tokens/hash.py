"""HMAC helpers for storing OAuth2 tokens without raw token values."""

import hashlib
import hmac


def hash_oauth2_token(
    *,
    token: str,
    secret: str,
) -> str:
    """Return a stable HMAC-SHA-256 digest for an OAuth2 token.

    Args:
        token (str): Raw access or refresh token received from a client.
        secret (str): Server-side HMAC secret.

    Returns:
        str: Hex-encoded token digest suitable for indexed storage.
    """
    return hmac.new(
        key=secret.encode("utf-8"),
        msg=token.encode("utf-8"),
        digestmod=hashlib.sha256,
    ).hexdigest()
