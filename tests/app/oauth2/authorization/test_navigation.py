"""Tests for OAuth2 authorization browser navigation."""

import pytest
from app.oauth2.authorization.navigation import authorization_login_url
from app.settings.root import Settings
from app.web.settings import AuthenticationUIMode, UISettings


pytestmark = pytest.mark.unit


def test_authorization_login_url_uses_builtin_login() -> None:
    """Append the opaque transaction to the built-in login page."""
    assert (
        authorization_login_url(Settings(), transaction_id="transaction-id")
        == "/login?transaction_id=transaction-id"
    )


def test_authorization_login_url_uses_external_login() -> None:
    """Append the opaque transaction to the configured external login page."""
    settings = Settings(
        ui=UISettings(
            authentication=AuthenticationUIMode.EXTERNAL,
            external_login_url="https://frontend.example/login",
        )
    )

    assert (
        authorization_login_url(settings, transaction_id="transaction-id")
        == "https://frontend.example/login?transaction_id=transaction-id"
    )
