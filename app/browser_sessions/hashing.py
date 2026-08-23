"""Privacy-preserving hashing helpers for browser-session authentication."""

import hashlib
import hmac


DUMMY_PASSWORD_HASH = (
    "$argon2id$v=19$m=65536,t=3,p=4$"  # noqa: S105
    "otqj5sZQgNrBwH1i8XLwOw$"
    "f4QHcD84dyLqRcMTNHcv5waHjqXY5WEz79HXMhSgfZ0"
)
"""Password hash used to equalize missing-user login verification cost."""


def hash_session_id(*, session_id: str, secret: str) -> str:
    """Return the database lookup digest for a raw browser session ID."""
    return hmac.new(
        key=secret.encode(),
        msg=session_id.encode(),
        digestmod=hashlib.sha256,
    ).hexdigest()


def hash_session_metadata(*, value: str | None, secret: str) -> str | None:
    """Return a privacy-preserving digest for optional session metadata."""
    if not value:
        return None
    return hmac.new(
        key=secret.encode(),
        msg=value.encode(),
        digestmod=hashlib.sha256,
    ).hexdigest()


def hash_auth_identifier(*, value: str, secret: str) -> str:
    """Return a privacy-preserving digest for an authentication identifier."""
    normalized_value = value.strip().lower()
    return hmac.new(
        key=secret.encode(),
        msg=normalized_value.encode(),
        digestmod=hashlib.sha256,
    ).hexdigest()
