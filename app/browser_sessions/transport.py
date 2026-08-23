"""Shared browser transport updates for newly authenticated sessions."""

from fastapi import Response

from app.browser_sessions.cookies import (
    delete_csrf_cookie,
    session_csrf_uses_cookie,
    set_csrf_cookie,
    set_session_cookie,
)
from app.browser_sessions.csrf import expose_csrf_header
from app.browser_sessions.dtos import LoginResultDTO
from app.browser_sessions.enums import CSRFTokenExposure
from app.browser_sessions.settings import CSRFSettings, SessionSettings


def apply_login_transport(
    response: Response,
    data: LoginResultDTO,
    *,
    csrf_settings: CSRFSettings,
    session_settings: SessionSettings,
) -> None:
    """Attach a new session and its matching CSRF state to a response."""
    set_session_cookie(response, data.session, session_settings)
    if csrf_settings.expose_token == CSRFTokenExposure.HEADER:
        expose_csrf_header(response, data.csrf, csrf_settings)
    if session_csrf_uses_cookie(csrf_settings):
        set_csrf_cookie(
            response,
            data.csrf,
            csrf_settings,
            max_age_seconds=session_settings.ttl_seconds,
        )
    else:
        delete_csrf_cookie(response, csrf_settings)
    response.headers["Cache-Control"] = "no-store"
