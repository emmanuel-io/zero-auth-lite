"""Tests for reusable API dependency helpers."""

import pytest
from app.api.errors import InvalidPublicIdError
from app.public_ids import PublicId

from app.api.dependencies import ids


pytestmark = pytest.mark.unit

PUBLIC_ID_VALUE = PublicId(1234567890123456789)


@pytest.mark.parametrize(
    ("parser", "formatter", "prefix"),
    [
        (ids.parse_user_id, ids.format_user_id, "usr"),
        (ids.parse_organization_id, ids.format_organization_id, "org"),
    ],
)
def test_public_id_parse_and_format_round_trip(
    parser: object,
    formatter: object,
    prefix: str,
) -> None:
    """Assert public ID helpers parse and format prefixed identifiers."""
    formatted = formatter(PUBLIC_ID_VALUE)

    assert formatted == f"{prefix}_128GGYHYYK08N"
    assert parser(formatted) == PUBLIC_ID_VALUE


@pytest.mark.parametrize(
    "value",
    [
        "usr1234567890123456789",
        "org_1234567890123456789",
        "usr_notdigits",
        "usr_1",
        "usr_1234567890123456789",
        "usr_128ggyhyyk08n",
    ],
)
def test_parse_user_id_rejects_malformed_values(value: str) -> None:
    """Assert malformed public identifiers raise the domain error."""
    with pytest.raises(InvalidPublicIdError):
        ids.parse_user_id(value)
