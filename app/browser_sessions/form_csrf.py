"""CSRF helpers for ordinary server-rendered HTML forms."""

import secrets

from fastapi import Request, Response

from app.browser_sessions.csrf import validate_request_origin
from app.browser_sessions.errors import (
    CSRFCookieHeaderMismatchError,
    CSRFMissingCookieError,
    CSRFMissingHeaderError,
)
from app.browser_sessions.settings import CSRFSettings
from app.browser_sessions.specs import SessionSpecs
from app.core.compare import constant_time_equals


FORM_CSRF_COOKIE_SUFFIX = "-form"


def _form_cookie_name(csrf_settings: CSRFSettings) -> str:
    """Keep anonymous form state separate from an authenticated session token."""
    return f"{csrf_settings.cookie_name}{FORM_CSRF_COOKIE_SUFFIX}"


def create_pre_session_form_csrf() -> str:
    """Create anonymous double-submit state for a hidden form field."""
    return secrets.token_urlsafe(SessionSpecs.TOKEN_BYTES)


def set_pre_session_form_csrf_cookie(
    response: Response,
    csrf_token: str,
    csrf_settings: CSRFSettings,
) -> None:
    """Attach anonymous form state without replacing session-owned CSRF state."""
    response.set_cookie(
        key=_form_cookie_name(csrf_settings),
        value=csrf_token,
        httponly=True,
        secure=csrf_settings.cookie_secure,
        samesite=csrf_settings.cookie_same_site.value,
        max_age=csrf_settings.ttl_seconds,
        path="/",
        domain=csrf_settings.cookie_domain,
    )


def validate_pre_session_form_csrf(
    *,
    request: Request,
    csrf_token: str | None,
    csrf_settings: CSRFSettings,
) -> None:
    """Validate origin-bound anonymous form state."""
    validate_request_origin(request=request, csrf_settings=csrf_settings)
    if not csrf_token:
        raise CSRFMissingHeaderError
    cookie_token = request.cookies.get(_form_cookie_name(csrf_settings))
    if cookie_token is None:
        raise CSRFMissingCookieError
    if not constant_time_equals(cookie_token, csrf_token):
        raise CSRFCookieHeaderMismatchError
