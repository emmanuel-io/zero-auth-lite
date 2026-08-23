"""Tests for OAuth2 administration public identifiers."""

import pytest
from app.oauth2.public_ids import format_oauth2_session_id, parse_oauth2_session_id
from app.public_ids import PublicId


pytestmark = pytest.mark.unit


def test_oauth2_session_public_id_round_trip() -> None:
    """Round-trip an OAuth2 session through its resource prefix."""
    public_id = PublicId(303)

    formatted = format_oauth2_session_id(public_id)

    assert formatted == "oas_000000000009F"
    assert parse_oauth2_session_id(formatted) == public_id


@pytest.mark.parametrize(
    "value",
    [
        "oas_0000000000000000303",
        "oas_000000000009f",
        "ses_000000000009F",
        "oau_000000000009F",
        "oas_00000000000OI",
    ],
)
def test_oauth2_session_public_id_rejects_noncanonical_values(value: str) -> None:
    """Reject noncanonical, wrong-prefix, and ambiguous spellings."""
    with pytest.raises(ValueError, match="Invalid OAuth2 session identifier"):
        parse_oauth2_session_id(value)
