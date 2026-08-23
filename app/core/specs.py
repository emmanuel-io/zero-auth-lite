"""Shared representation limits derived from stable technical formats."""

import hashlib
from typing import Final


BITS_PER_BYTE: Final[int] = 8
UUID_BYTES: Final[int] = 16
HEXADECIMAL_CHARACTERS_PER_BYTE: Final[int] = 2
UUID_HEX_LENGTH: Final[int] = UUID_BYTES * HEXADECIMAL_CHARACTERS_PER_BYTE
"""Length of one RFC 9562 UUID encoded as hexadecimal text."""
UUID_HEX_PATTERN: Final[str] = rf"^[0-9a-f]{{{UUID_HEX_LENGTH}}}$"
"""Canonical lowercase hexadecimal UUID representation."""

SHA256_HEX_LENGTH: Final[int] = (
    hashlib.sha256().digest_size * HEXADECIMAL_CHARACTERS_PER_BYTE
)
"""Length of a SHA-256 digest encoded as hexadecimal text."""

EMAIL_ADDRESS_LENGTH_MAX: Final[int] = 254
"""Maximum mailbox length accepted and persisted by Zero Auth Lite."""


def unpadded_urlsafe_base64_length(byte_count: int) -> int:
    """Return the encoded length produced for unpadded URL-safe base64 bytes."""
    return (byte_count * BITS_PER_BYTE + 5) // 6
