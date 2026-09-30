"""Tests for expected and unexpected OAuth2 grant parsing failures."""

import pytest
from app.oauth2.errors import OAuth2ProtocolError
from app.oauth2.specs import OAuth2Specs

from app.oauth2.grants import parsing


pytestmark = pytest.mark.unit


def test_token_grant_validation_error_becomes_invalid_request() -> None:
    """Translate invalid client input into the OAuth2 protocol boundary."""
    fields: dict[str, object] = {
        "grant_type": "refresh_token",
        "refresh_token": "x" * (OAuth2Specs.PROTOCOL_VALUE_LENGTH_MAX + 1),
    }

    with pytest.raises(OAuth2ProtocolError) as exc_info:
        parsing.parse_token_grant(fields)

    assert exc_info.value.error == "invalid_request"


def test_token_grant_unexpected_error_propagates(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Do not disguise an internal grant-construction regression as client input."""

    def fail(**_fields: object) -> None:
        msg = "grant parser regression"
        raise RuntimeError(msg)

    monkeypatch.setattr(parsing, "RefreshTokenGrantRequest", fail)

    with pytest.raises(RuntimeError, match="grant parser regression"):
        parsing.parse_token_grant(
            {"grant_type": "refresh_token", "refresh_token": "refresh-token"}
        )
