"""Helpers for OAuth2 device authorization codes."""

import secrets

from app.oauth2.specs import OAuth2Specs


def create_device_code() -> str:
    """Return a new opaque, URL-safe device code."""
    return secrets.token_urlsafe(OAuth2Specs.DEVICE_CODE_BYTES)


def create_user_code() -> str:
    """Return an unambiguous, grouped code suitable for manual entry."""
    alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
    value = "".join(secrets.choice(alphabet) for _ in range(8))
    return f"{value[:4]}-{value[4:]}"
