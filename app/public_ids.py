"""Types and numeric codec for public Snowflake identifiers."""

from typing import NewType


PublicId = NewType("PublicId", int)

CROCKFORD_BASE32_ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
PUBLIC_ID_PAYLOAD_LENGTH = 13
MAX_PUBLIC_ID = 2**63 - 1
PUBLIC_ID_PAYLOAD_PATTERN = r"[0-7][0-9A-HJKMNP-TV-Z]{12}"

_CROCKFORD_BASE32_VALUES = {
    character: value for value, character in enumerate(CROCKFORD_BASE32_ALPHABET)
}


def encode_public_id_payload(value: int) -> str:
    """Encode a signed-int64-compatible value as canonical Crockford Base32.

    Args:
        value: Non-negative integer that fits in a signed 64-bit database column.

    Returns:
        The value as exactly 13 uppercase Crockford Base32 characters.

    Raises:
        ValueError: If the value is not an integer in the supported range.
    """
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or not 0 <= value <= MAX_PUBLIC_ID
    ):
        msg = f"Public identifier value must be between 0 and {MAX_PUBLIC_ID}"
        raise ValueError(msg)

    characters: list[str] = []
    remaining = value
    while remaining:
        remaining, digit = divmod(remaining, len(CROCKFORD_BASE32_ALPHABET))
        characters.append(CROCKFORD_BASE32_ALPHABET[digit])

    payload = "".join(reversed(characters))
    return payload.rjust(PUBLIC_ID_PAYLOAD_LENGTH, "0")


def decode_public_id_payload(payload: str) -> int:
    """Decode one canonical Crockford Base32 public-ID payload.

    Args:
        payload: Exactly 13 uppercase canonical Crockford Base32 characters.

    Returns:
        The decoded signed-int64-compatible integer.

    Raises:
        ValueError: If the payload is not canonical or exceeds signed int64.
    """
    if not isinstance(payload, str) or len(payload) != PUBLIC_ID_PAYLOAD_LENGTH:
        msg = "Public identifier payload must contain exactly 13 characters"
        raise ValueError(msg)

    value = 0
    for character in payload:
        try:
            digit = _CROCKFORD_BASE32_VALUES[character]
        except KeyError as exc:
            msg = "Public identifier payload is not canonical Crockford Base32"
            raise ValueError(msg) from exc
        value = value * len(CROCKFORD_BASE32_ALPHABET) + digit

    if value > MAX_PUBLIC_ID:
        msg = f"Public identifier value must be between 0 and {MAX_PUBLIC_ID}"
        raise ValueError(msg)
    return value


def public_id_pattern(prefix: str) -> str:
    """Build the anchored pattern for one prefixed public identifier."""
    return rf"^{prefix}_{PUBLIC_ID_PAYLOAD_PATTERN}$"


def format_prefixed_public_id(public_id: PublicId | int, *, prefix: str) -> str:
    """Format a public identifier with its resource prefix."""
    return f"{prefix}_{encode_public_id_payload(public_id)}"


def parse_prefixed_public_id(value: str, *, prefix: str) -> PublicId:
    """Decode a public identifier after validating its resource prefix."""
    marker = f"{prefix}_"
    if not value.startswith(marker):
        msg = f"Invalid {prefix} public identifier"
        raise ValueError(msg)
    return PublicId(decode_public_id_payload(value.removeprefix(marker)))
