"""Tests for canonical public identity formatting."""

from collections.abc import Callable

import pytest
from app.identity.public_ids import (
    format_organization_id,
    format_user_id,
    parse_organization_id,
    parse_user_id,
)
from app.public_ids import PublicId


pytestmark = pytest.mark.unit


def test_public_identity_format_is_canonical() -> None:
    """Format public identities with their single supported prefixes."""
    assert format_user_id(PublicId(42)) == "usr_000000000001A"
    assert format_organization_id(PublicId(42)) == "org_000000000001A"


@pytest.mark.parametrize(
    ("parser", "value"),
    [
        (parse_user_id, "user:42"),
        (parse_organization_id, "organization:42"),
        (parse_user_id, "usr_42"),
        (parse_organization_id, "org_42"),
        (parse_user_id, "usr_0000000000000000042"),
        (parse_user_id, "org_000000000001A"),
        (parse_organization_id, "usr_000000000001A"),
    ],
)
def test_public_identity_parser_rejects_invalid_formats(
    parser: Callable[[str], PublicId], value: str
) -> None:
    """Reject malformed, noncanonical, and wrong-resource identifiers."""
    with pytest.raises(ValueError, match="Invalid public identifier"):
        parser(value)


def test_public_identity_parser_accepts_canonical_formats() -> None:
    """Parse the canonical prefixed public identity formats."""
    assert parse_user_id("usr_000000000001A") == PublicId(42)
    assert parse_organization_id("org_000000000001A") == PublicId(42)
