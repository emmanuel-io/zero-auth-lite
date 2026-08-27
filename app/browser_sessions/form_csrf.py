"""CSRF helpers for ordinary server-rendered HTML forms."""

import secrets

from fastapi import Request, Response

from app.browser_sessions.csrf import validate_request_origin
from app.browser_sessions.errors import (
    CSRFCookieHeaderMismatchError,
    CSRFFormOriginMismatchError,
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


def _form_cookie_values(request: Request, csrf_settings: CSRFSettings) -> list[str]:
    """Return every same-named cookie sent across domains or paths."""
    cookie_name = _form_cookie_name(csrf_settings)
    values: list[str] = []
    for raw_cookie_header in request.headers.getlist("cookie"):
        for cookie_pair in raw_cookie_header.split(";"):
            name, separator, value = cookie_pair.partition("=")
            if separator and name.strip() == cookie_name:
                values.append(value.strip())
    collapsed_value = request.cookies.get(cookie_name)
    if collapsed_value is not None and collapsed_value not in values:
        values.append(collapsed_value)
    return values


def create_pre_session_form_csrf() -> str:
    """Create anonymous double-submit state for a hidden form field."""
    return secrets.token_urlsafe(SessionSpecs.TOKEN_BYTES)


def get_or_create_pre_session_form_csrf(
    request: Request, csrf_settings: CSRFSettings
) -> str:
    """Reuse active anonymous form state so concurrent forms remain valid."""
    existing_token = request.cookies.get(_form_cookie_name(csrf_settings))
    return existing_token or create_pre_session_form_csrf()


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
    try:
        validate_request_origin(request=request, csrf_settings=csrf_settings)
    except CSRFCookieHeaderMismatchError as exc:
        raise CSRFFormOriginMismatchError from exc
    if not csrf_token:
        raise CSRFMissingHeaderError
    cookie_tokens = _form_cookie_values(request, csrf_settings)
    if not cookie_tokens:
        raise CSRFMissingCookieError
    matches_cookie = False
    for cookie_token in cookie_tokens:
        matches_cookie |= constant_time_equals(cookie_token, csrf_token)
    if not matches_cookie:
        raise CSRFCookieHeaderMismatchError
