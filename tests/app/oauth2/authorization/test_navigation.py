"""Tests for OAuth2 authorization browser navigation."""

import pytest
from app.oauth2.authorization.http import (
    authorization_interaction_entry_url,
    map_authorization_error,
)
from app.oauth2.error_codes import OAuth2ErrorCode, OAuth2ValidationReason
from app.settings.root import Settings
from app.settings.ui import (
    IdentityWorkflowUIMode,
    OAuth2InteractionUIMode,
    UISettings,
)


pytestmark = pytest.mark.unit


def test_invalid_redirect_reason_maps_to_public_invalid_request() -> None:
    """Keep an internal redirect reason out of the public error vocabulary."""
    error = map_authorization_error(
        ValueError(OAuth2ValidationReason.INVALID_REDIRECT_URI)
    )

    assert error.error is OAuth2ErrorCode.INVALID_REQUEST


def test_authorization_interaction_entry_uses_builtin_login() -> None:
    """Append the opaque transaction to the built-in login page."""
    assert (
        authorization_interaction_entry_url(Settings(), transaction_id="transaction-id")
        == "/login?transaction_id=transaction-id"
    )


def test_authorization_interaction_entry_uses_external_ui() -> None:
    """Append the opaque transaction to the external OAuth2 interaction page."""
    settings = Settings(
        ui=UISettings(
            identity_workflow_mode=IdentityWorkflowUIMode.EXTERNAL,
            oauth2_interaction=OAuth2InteractionUIMode.EXTERNAL,
            urls={
                "authorization_interaction": (
                    "https://frontend.example/oauth2/interaction"
                ),
                "device_interaction": "https://frontend.example/oauth2/interaction",
            },
        ),
    )

    assert authorization_interaction_entry_url(
        settings, transaction_id="transaction-id"
    ) == ("https://frontend.example/oauth2/interaction?transaction_id=transaction-id")
