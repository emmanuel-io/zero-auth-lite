"""Tests for expected and unexpected OAuth2 parsing failures."""

import pytest
from app.oauth2.errors import InvalidClientError, OAuth2ProtocolError
from app.oauth2.grants import parsing
from app.oauth2.specs import OAuth2Specs

from app.oauth2.clients import auth


pytestmark = pytest.mark.unit


def test_token_grant_validation_error_becomes_invalid_request() -> None:
    """Translate invalid client input into the OAuth2 protocol boundary."""
    fields = {
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


@pytest.mark.parametrize(
    "authorization",
    ["Basic !!!", "Basic bm8tY29sb24=", "Basic /w=="],
)
def test_malformed_basic_header_becomes_invalid_client(authorization: str) -> None:
    """Translate expected Base64, split, and Unicode failures."""
    with pytest.raises(InvalidClientError):
        auth._parse_basic_header(authorization)  # noqa: SLF001


def test_basic_header_unexpected_error_propagates(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Do not disguise an internal Basic-decoder regression as credentials."""

    def fail(*_args: object, **_kwargs: object) -> bytes:
        msg = "basic parser regression"
        raise RuntimeError(msg)

    monkeypatch.setattr(auth.base64, "b64decode", fail)

    with pytest.raises(RuntimeError, match="basic parser regression"):
        auth._parse_basic_header("Basic Y2xpZW50OnNlY3JldA==")  # noqa: SLF001
