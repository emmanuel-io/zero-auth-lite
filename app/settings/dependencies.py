"""Settings dependency."""

from typing import Annotated, TYPE_CHECKING

from fastapi import Depends, Request

from app.settings.state import get_settings_snapshot


if TYPE_CHECKING:
    from app.browser_sessions.settings import BrowserSessionSettings, CSRFSettings
    from app.oauth2.settings import OAuth2Settings
    from app.settings.root import Settings
    from app.workflow_tokens.settings import WorkflowTokenSettings


def get_settings(
    request: Request,
) -> "Settings":
    """Return the immutable settings snapshot stored at startup."""
    return get_settings_snapshot(request.app)


SettingsDep = Annotated["Settings", Depends(get_settings)]


def get_browser_session_settings(
    settings: SettingsDep,
) -> "BrowserSessionSettings":
    """Return the browser-session settings section."""
    return settings.browser_session


BrowserSessionSettingsDep = Annotated[
    "BrowserSessionSettings", Depends(get_browser_session_settings)
]


def get_csrf_settings(
    settings: SettingsDep,
) -> "CSRFSettings":
    """Return the CSRF settings section."""
    return settings.browser_session.csrf


CSRFSettingsDep = Annotated["CSRFSettings", Depends(get_csrf_settings)]


def get_oauth2_settings(
    settings: SettingsDep,
) -> "OAuth2Settings":
    """Return the OAuth2 settings section."""
    return settings.oauth2


OAuth2SettingsDep = Annotated["OAuth2Settings", Depends(get_oauth2_settings)]


def get_workflow_token_settings(
    settings: SettingsDep,
) -> "WorkflowTokenSettings":
    """Provide identity workflow-token settings from the root snapshot."""
    return settings.identity_workflow.workflow_tokens


WorkflowTokenSettingsDep = Annotated[
    "WorkflowTokenSettings",
    Depends(get_workflow_token_settings),
]
