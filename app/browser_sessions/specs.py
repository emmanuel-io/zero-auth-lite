"""Shared browser-session persistence and validation contracts."""

from typing import Final

from app.core.specs import unpadded_urlsafe_base64_length


class SessionSpecs:
    """Browser-session token and metadata limits."""

    TOKEN_BYTES: Final[int] = 32
    TOKEN_LENGTH: Final[int] = unpadded_urlsafe_base64_length(TOKEN_BYTES)
    REVOCATION_REASON_LENGTH_MAX: Final[int] = 64
