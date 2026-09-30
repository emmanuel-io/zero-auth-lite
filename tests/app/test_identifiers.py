"""Tests for the shared UUIDv4 identifier boundary."""

from uuid import NAMESPACE_URL, UUID, uuid4, uuid5

import pytest
from app.identifiers import parse_uuid4
from pydantic import BaseModel, UUID4, ValidationError


pytestmark = pytest.mark.unit


class UUIDResponse(BaseModel):
    """Minimal response model exercising canonical UUID serialization."""

    id: UUID4


@pytest.mark.parametrize(
    "representation",
    [
        "550e8400-e29b-41d4-a716-446655440000",
        "550E8400-E29B-41D4-A716-446655440000",
        "550e8400e29b41d4a716446655440000",
        "{550e8400-e29b-41d4-a716-446655440000}",
    ],
)
def test_uuid4_parser_accepts_pydantic_representations(representation: str) -> None:
    """Accept UUIDv4 spellings supported by the Pydantic HTTP boundary."""
    assert parse_uuid4(representation) == UUID("550e8400-e29b-41d4-a716-446655440000")


@pytest.mark.parametrize("value", ["not-a-uuid", str(uuid5(NAMESPACE_URL, "user"))])
def test_uuid4_parser_rejects_invalid_or_other_version_values(value: str) -> None:
    """Reject malformed UUIDs and UUIDs from another version."""
    with pytest.raises(ValueError, match="Invalid UUIDv4"):
        parse_uuid4(value)


def test_uuid4_response_uses_canonical_lowercase_hyphenated_text() -> None:
    """Serialize UUID objects with the canonical public representation."""
    value = uuid4()

    response = UUIDResponse(id=value)

    assert response.model_dump_json() == f'{{"id":"{value}"}}'


def test_uuid4_response_rejects_other_uuid_versions() -> None:
    """Keep the declarative HTTP contract restricted to UUIDv4."""
    with pytest.raises(ValidationError):
        UUIDResponse(id=uuid5(NAMESPACE_URL, "user"))
