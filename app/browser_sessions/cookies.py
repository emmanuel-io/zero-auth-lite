"""Cookie helpers for browser-session authentication."""

from fastapi import Request, Response

from app.browser_sessions.enums import CSRFPattern, CSRFTokenExposure
from app.browser_sessions.settings import CSRFSettings, SessionSettings


def get_session_cookie(
    request: Request, session_settings: SessionSettings
) -> str | None:
    """Return the raw browser session cookie when present."""
    return request.cookies.get(session_settings.cookie_name)


def set_session_cookie(
    response: Response,
    session_id: str,
    session_settings: SessionSettings,
    *,
    max_age_seconds: int | None = None,
) -> None:
    """Set or refresh the configured HttpOnly browser session cookie.

    A newly authenticated session uses the configured sliding lifetime. Callers
    resolving an existing SQL session pass its effective remaining lifetime so
    browser transport never outlives server-side authority.
    """
    response.set_cookie(
        key=session_settings.cookie_name,
        value=session_id,
        httponly=True,
        secure=session_settings.cookie_secure,
        samesite=session_settings.cookie_same_site.value,
        max_age=(
            session_settings.ttl_seconds if max_age_seconds is None else max_age_seconds
        ),
        path="/",
        domain=session_settings.cookie_domain,
    )


def delete_session_cookie(
    response: Response, session_settings: SessionSettings
) -> None:
    """Delete the configured browser session cookie."""
    response.delete_cookie(
        key=session_settings.cookie_name,
        httponly=True,
        secure=session_settings.cookie_secure,
        samesite=session_settings.cookie_same_site.value,
        path="/",
        domain=session_settings.cookie_domain,
    )


def set_csrf_cookie(
    response: Response,
    csrf_token: str,
    csrf_settings: CSRFSettings,
    *,
    max_age_seconds: int | None = None,
) -> None:
    """Set or refresh the configured CSRF cookie.

    Pre-session cookies use the CSRF lifetime. Session-bound cookies pass the
    browser-session lifetime explicitly so both cookies slide together.
    """
    response.set_cookie(
        key=csrf_settings.cookie_name,
        value=csrf_token,
        httponly=csrf_settings.expose_token == CSRFTokenExposure.HEADER,
        secure=csrf_settings.cookie_secure,
        samesite=csrf_settings.cookie_same_site.value,
        max_age=(
            csrf_settings.ttl_seconds if max_age_seconds is None else max_age_seconds
        ),
        path="/",
        domain=csrf_settings.cookie_domain,
    )


def session_csrf_uses_cookie(csrf_settings: CSRFSettings) -> bool:
    """Return whether authenticated CSRF state needs a browser cookie."""
    return (
        csrf_settings.pattern == CSRFPattern.DOUBLE_SUBMIT
        or csrf_settings.expose_token == CSRFTokenExposure.COOKIE
    )


def delete_csrf_cookie(response: Response, csrf_settings: CSRFSettings) -> None:
    """Delete the configured CSRF cookie."""
    response.delete_cookie(
        key=csrf_settings.cookie_name,
        httponly=csrf_settings.expose_token == CSRFTokenExposure.HEADER,
        secure=csrf_settings.cookie_secure,
        samesite=csrf_settings.cookie_same_site.value,
        path="/",
        domain=csrf_settings.cookie_domain,
    )
