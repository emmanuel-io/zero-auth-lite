"""Settings dependency."""

from typing import Annotated, TYPE_CHECKING

from fastapi import Depends, Request

from app.settings.state import get_settings_snapshot


if TYPE_CHECKING:
    from app.auth_tokens.settings import AuthTokenSettings
    from app.browser_sessions.settings import CSRFSettings, SessionSettings
    from app.mail.settings import MailSettings
    from app.oauth2.settings import OAuth2Settings
    from app.settings.root import Settings


def get_settings(
    request: Request,
) -> "Settings":
    """Return the immutable settings snapshot stored at startup."""
    return get_settings_snapshot(request.app)


SettingsDep = Annotated["Settings", Depends(get_settings)]


def get_session_settings(
    settings: SettingsDep,
) -> "SessionSettings":
    """Return the browser-session settings section."""
    return settings.session


SessionSettingsDep = Annotated["SessionSettings", Depends(get_session_settings)]


def get_csrf_settings(
    settings: SettingsDep,
) -> "CSRFSettings":
    """Return the CSRF settings section."""
    return settings.session.csrf


CSRFSettingsDep = Annotated["CSRFSettings", Depends(get_csrf_settings)]


def get_oauth2_settings(
    settings: SettingsDep,
) -> "OAuth2Settings":
    """Return the OAuth2 settings section."""
    return settings.oauth2


OAuth2SettingsDep = Annotated["OAuth2Settings", Depends(get_oauth2_settings)]


def get_mail_settings(
    settings: SettingsDep,
) -> "MailSettings":
    """Return the transactional-mail settings section."""
    return settings.mail


MailSettingsDep = Annotated["MailSettings", Depends(get_mail_settings)]


def get_auth_token_settings(
    settings: SettingsDep,
) -> "AuthTokenSettings":
    """Provide auth workflow token settings from the main Settings."""
    return settings.auth.tokens


AuthTokenSettingsDep = Annotated[
    "AuthTokenSettings",
    Depends(get_auth_token_settings),
]
