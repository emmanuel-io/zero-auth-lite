"""Canonical correlation identifier representation."""

from uuid import UUID, uuid4

from app.core.specs import UUID_HEX_LENGTH


CORRELATION_ID_LENGTH = UUID_HEX_LENGTH
"""Length of one RFC 9562 UUID encoded as lowercase hexadecimal text."""


def generate_correlation_id() -> str:
    """Generate one UUIDv4 as 32 lowercase hexadecimal characters."""
    return uuid4().hex


def normalize_correlation_id(value: str) -> str:
    """Normalize an accepted UUID representation to canonical hexadecimal text."""
    return UUID(value).hex
