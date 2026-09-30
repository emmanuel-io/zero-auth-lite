"""Tests for settings-driven OpenAPI tag metadata."""

import pytest
from app.browser_sessions.settings import BrowserSessionSettings
from app.main import create_app
from app.oauth2.settings import OAuth2Settings
from app.settings.identity_workflow import IdentityWorkflowSettings
from app.settings.root import Settings
from app.settings.ui import (
    IdentityWorkflowUIMode,
    ManagementAuthenticationMode,
    OAuth2InteractionUIMode,
    UISettings,
)


pytestmark = pytest.mark.unit

HTTP_METHODS = {"delete", "get", "head", "options", "patch", "post", "put", "trace"}


def _external_ui() -> UISettings:
    """Return an external authentication UI with a valid login destination."""
    return UISettings(
        identity_workflow_mode=IdentityWorkflowUIMode.EXTERNAL,
        management_authentication=ManagementAuthenticationMode.EXTERNAL,
        urls={
            "login": "https://frontend.test/login",
            "logout": "https://frontend.test/logout",
        },
    )


def _sessionless_settings() -> Settings:
    """Return a valid machine-to-machine server configuration."""
    return Settings(
        browser_session=BrowserSessionSettings(enabled=False),
        identity_workflow=IdentityWorkflowSettings(registration_enabled=False),
        ui=UISettings(
            oauth2_interaction=OAuth2InteractionUIMode.DISABLED,
        ),
        oauth2=OAuth2Settings().model_copy(
            update={
                "authorization_code_enabled": False,
                "refresh_token_enabled": False,
                "device_code_enabled": False,
                "oidc_enabled": False,
            }
        ),
    )


@pytest.mark.parametrize(
    "settings",
    [
        Settings(browser_session=BrowserSessionSettings(), ui=UISettings()),
        Settings(
            browser_session=BrowserSessionSettings(),
            ui=_external_ui(),
        ),
        Settings(
            browser_session=BrowserSessionSettings(),
            ui=UISettings(organization_admin_enabled=True, operator_enabled=False),
        ),
        Settings(
            browser_session=BrowserSessionSettings(),
            ui=UISettings(organization_admin_enabled=False, operator_enabled=True),
        ),
        Settings(
            browser_session=BrowserSessionSettings(),
            oauth2=OAuth2Settings.disabled(),
            ui=UISettings(),
        ),
        _sessionless_settings(),
    ],
)
def test_openapi_metadata_matches_mounted_route_tags(
    settings: Settings,
) -> None:
    """Declare every mounted tag and avoid advertising unmounted tag groups."""
    schema = create_app(settings).openapi()
    metadata_tags = {tag["name"] for tag in schema["tags"]}
    operation_tags = {
        tag
        for path_item in schema["paths"].values()
        for method, operation in path_item.items()
        if method in HTTP_METHODS
        for tag in operation.get("tags", [])
    }

    assert metadata_tags == operation_tags
