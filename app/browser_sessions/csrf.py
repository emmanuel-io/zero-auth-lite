"""CSRF helpers for browser-session authentication."""

from urllib.parse import urlparse

from fastapi import Request, Response

from app.browser_sessions.enums import CSRFPattern
from app.browser_sessions.errors import (
    CSRFCookieHeaderMismatchError,
    CSRFHeaderSessionMismatchError,
    CSRFMissingCookieError,
    CSRFMissingHeaderError,
    SessionInvalidError,
)
from app.browser_sessions.lifecycle import SessionLifecycleService
from app.browser_sessions.settings import CSRFSettings
from app.core.compare import constant_time_equals


CSRF_UNSAFE_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})


def _origin_from_url(value: str) -> str | None:
    """Return scheme and authority from an origin-bearing URL."""
    parsed = urlparse(value)
    if not parsed.scheme or not parsed.netloc:
        return None
    return f"{parsed.scheme}://{parsed.netloc}"


def _is_same_origin_document_navigation(request: Request) -> bool:
    """Recognize browser-authenticated same-origin navigation metadata."""
    return (
        request.headers.get("sec-fetch-site", "").casefold() == "same-origin"
        and request.headers.get("sec-fetch-mode", "").casefold() == "navigate"
        and request.headers.get("sec-fetch-dest", "").casefold() == "document"
    )


def expose_csrf_header(
    response: Response, csrf_token: str, csrf_settings: CSRFSettings
) -> None:
    """Expose a CSRF token through the configured response header."""
    response.headers[csrf_settings.header_name] = csrf_token


def validate_request_origin(request: Request, csrf_settings: CSRFSettings) -> None:
    """Validate Origin or Referer for an unsafe browser-session request."""
    if not csrf_settings.origin_check_enabled:
        return
    raw_origin = request.headers.get("origin") or request.headers.get("referer")
    if raw_origin is None:
        raise CSRFMissingHeaderError
    request_origin = f"{request.url.scheme}://{request.url.netloc}"
    trusted_origins = {request_origin, *csrf_settings.trusted_origins}
    if csrf_settings.public_origin is not None:
        trusted_origins.add(csrf_settings.public_origin)
    origin_is_trusted = _origin_from_url(raw_origin) in trusted_origins
    opaque_same_origin_navigation = (
        raw_origin.casefold() == "null" and _is_same_origin_document_navigation(request)
    )
    if not origin_is_trusted and not opaque_same_origin_navigation:
        raise CSRFCookieHeaderMismatchError


def validate_double_submit_csrf(request: Request, csrf_settings: CSRFSettings) -> None:
    """Validate double-submit CSRF inputs for an unsafe request."""
    validate_request_origin(request=request, csrf_settings=csrf_settings)
    csrf_header = request.headers.get(csrf_settings.header_name)
    if not csrf_header:
        raise CSRFMissingHeaderError
    csrf_cookie = request.cookies.get(csrf_settings.cookie_name)
    if csrf_cookie is None:
        raise CSRFMissingCookieError
    if not constant_time_equals(csrf_cookie, csrf_header):
        raise CSRFCookieHeaderMismatchError


async def require_logout_csrf_if_session_is_valid(
    *,
    request: Request,
    lifecycle_service: SessionLifecycleService,
    csrf_settings: CSRFSettings,
    session_id: str,
) -> bool:
    """Validate logout CSRF and report whether session authority remains valid."""
    try:
        session_csrf = await lifecycle_service.get_session_csrf(session_id=session_id)
    except SessionInvalidError:
        return False

    validate_request_origin(request=request, csrf_settings=csrf_settings)
    csrf_header = request.headers.get(csrf_settings.header_name)
    if not csrf_header:
        raise CSRFMissingHeaderError
    if csrf_settings.pattern == CSRFPattern.DOUBLE_SUBMIT:
        csrf_cookie = request.cookies.get(csrf_settings.cookie_name)
        if csrf_cookie is None:
            raise CSRFMissingCookieError
        if not constant_time_equals(csrf_cookie, csrf_header):
            raise CSRFCookieHeaderMismatchError
        return True
    if not constant_time_equals(csrf_header, session_csrf):
        raise CSRFHeaderSessionMismatchError
    return True
