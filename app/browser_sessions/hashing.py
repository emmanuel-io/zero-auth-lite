"""Privacy-preserving hashing helpers for browser-session authentication."""

import hashlib
import hmac

from app.browser_sessions.settings import BrowserSessionSettings


DUMMY_PASSWORD_HASH = (
    "$argon2id$v=19$m=65536,t=3,p=4$"  # noqa: S105
    "otqj5sZQgNrBwH1i8XLwOw$"
    "f4QHcD84dyLqRcMTNHcv5waHjqXY5WEz79HXMhSgfZ0"
)
# Equalizes password-verification cost when no matching user exists.

AUTH_IDENTIFIER_HASH_DOMAIN = b"auth-identifier"
IP_ADDRESS_HASH_DOMAIN = b"ip-address"
SESSION_ID_HASH_DOMAIN = b"session-id"
USER_AGENT_HASH_DOMAIN = b"user-agent"


def _keyed_digest(*, value: str, secret: str, domain: bytes) -> str:
    """Return a domain-separated HMAC digest."""
    return hmac.new(
        key=secret.encode(),
        msg=domain + b"\0" + value.encode(),
        digestmod=hashlib.sha256,
    ).hexdigest()


def hash_session_id(*, session_id: str, secret: str) -> str:
    """Return the database lookup digest for a raw browser session ID."""
    return _keyed_digest(
        value=session_id,
        secret=secret,
        domain=SESSION_ID_HASH_DOMAIN,
    )


def hash_configured_session_id(
    *, session_id: str, settings: BrowserSessionSettings
) -> str:
    """Return the database lookup digest using browser-session settings."""
    return hash_session_id(
        session_id=session_id,
        secret=settings.hash_secret.get_secret_value(),
    )


def hash_session_ip(*, value: str | None, secret: str) -> str | None:
    """Return a privacy-preserving digest for an optional source IP address."""
    if not value:
        return None
    return _keyed_digest(value=value, secret=secret, domain=IP_ADDRESS_HASH_DOMAIN)


def hash_session_user_agent(*, value: str | None, secret: str) -> str | None:
    """Return a privacy-preserving digest for an optional user agent."""
    if not value:
        return None
    return _keyed_digest(value=value, secret=secret, domain=USER_AGENT_HASH_DOMAIN)


def hash_auth_identifier(*, value: str, secret: str) -> str:
    """Return a privacy-preserving digest for an authentication identifier."""
    normalized_value = value.strip().lower()
    return _keyed_digest(
        value=normalized_value,
        secret=secret,
        domain=AUTH_IDENTIFIER_HASH_DOMAIN,
    )
