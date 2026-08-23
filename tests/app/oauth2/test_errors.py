"""Tests for internal OAuth2 bearer error categories."""

import pytest
from app.oauth2.errors import (
    OAuth2AccessTokenInvalidError,
    OAuth2SessionInvalidError,
)


pytestmark = pytest.mark.unit


def test_bearer_errors_share_a_transport_neutral_application_contract() -> None:
    """Distinguish causes internally behind one access-token error contract."""
    assert OAuth2AccessTokenInvalidError.code == "INVALID_ACCESS_TOKEN"
    assert OAuth2AccessTokenInvalidError.message == "Invalid access token."
    assert OAuth2SessionInvalidError.code == "INVALID_ACCESS_TOKEN"
    assert OAuth2SessionInvalidError.message == "Invalid access token."
