"""Tests for canonical OAuth2 error categories."""

from typing import cast

import pytest
from app.oauth2.error_codes import OAuth2ErrorCode
from app.oauth2.errors import (
    OAuth2AccessTokenInvalidError,
    OAuth2ProtocolError,
    OAuth2TokenSessionInvalidError,
)


pytestmark = pytest.mark.unit


def test_bearer_errors_share_a_transport_neutral_application_contract() -> None:
    """Distinguish causes internally behind one access-token error contract."""
    assert OAuth2AccessTokenInvalidError.code == "INVALID_ACCESS_TOKEN"
    assert OAuth2AccessTokenInvalidError.message == "Invalid access token."
    assert OAuth2TokenSessionInvalidError.code == "INVALID_ACCESS_TOKEN"
    assert OAuth2TokenSessionInvalidError.message == "Invalid access token."


def test_protocol_error_requires_a_canonical_code() -> None:
    """Prevent arbitrary strings from becoming public OAuth2 error values."""
    with pytest.raises(TypeError, match="canonical OAuth2ErrorCode"):
        OAuth2ProtocolError(error=cast("OAuth2ErrorCode", "unknown_error"))


def test_protocol_error_codes_keep_the_public_vocabulary() -> None:
    """Keep the wire vocabulary explicit and deterministically ordered."""
    assert [code.value for code in OAuth2ErrorCode] == [
        "invalid_request",
        "invalid_client",
        "invalid_grant",
        "unauthorized_client",
        "unsupported_grant_type",
        "invalid_scope",
        "access_denied",
        "authorization_pending",
        "slow_down",
        "expired_token",
        "unsupported_token_type",
        "unsupported_response_type",
        "server_error",
        "temporarily_unavailable",
        "invalid_token",
        "insufficient_scope",
    ]
