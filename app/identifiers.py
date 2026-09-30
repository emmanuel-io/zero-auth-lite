"""Shared parsing for UUIDv4 values received outside typed HTTP models."""

from uuid import UUID

from pydantic import TypeAdapter, UUID4, ValidationError


_UUID4_ADAPTER = TypeAdapter(UUID4)


def parse_uuid4(value: str) -> UUID:
    """Parse a UUIDv4 using the same normalization as Pydantic HTTP fields.

    Raises:
        ValueError: If the value is not a valid UUIDv4 representation.
    """
    try:
        return _UUID4_ADAPTER.validate_python(value)
    except ValidationError as exc:
        msg = "Invalid UUIDv4"
        raise ValueError(msg) from exc
