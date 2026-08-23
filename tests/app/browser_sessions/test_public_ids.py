"""Tests for browser-session public identifiers."""

import pytest
from app.api.v1.me.schemas import CurrentUserBrowserSessionResponse
from app.browser_sessions.public_ids import (
    format_browser_session_id,
    parse_browser_session_id,
)
from app.public_ids import PublicId


pytestmark = pytest.mark.unit


def test_browser_session_api_schema_calls_the_external_identifier_id() -> None:
    """Assert the persistence distinction does not leak into the API schema."""
    properties = CurrentUserBrowserSessionResponse.model_json_schema()["properties"]

    assert "id" in properties
    assert "public_id" not in properties


def test_browser_session_public_id_round_trip() -> None:
    """Assert browser session identifiers use a stable external format."""
    public_id = PublicId(1_900_000_004_123_456)

    formatted = format_browser_session_id(public_id)

    assert formatted == "ses_001P018WN3AT0"
    assert parse_browser_session_id(formatted) == public_id


@pytest.mark.parametrize(
    "value",
    [
        "1",
        "ses_1",
        "ses_0001900000004123456",
        "oas_001P018WN3AT0",
        "ses_not-a-number",
    ],
)
def test_browser_session_public_id_rejects_internal_or_malformed_values(
    value: str,
) -> None:
    """Assert raw and incorrectly namespaced identifiers are rejected."""
    with pytest.raises(ValueError, match="Invalid browser session identifier"):
        parse_browser_session_id(value)
