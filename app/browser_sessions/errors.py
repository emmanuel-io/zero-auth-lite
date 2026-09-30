"""Session authentication exceptions."""

from typing import ClassVar

from fastapi import status

from app.core.errors.base import AppError


NO_STORE_HEADERS = {"Cache-Control": "no-store", "Pragma": "no-cache"}


class BrowserSessionInvalidError(AppError):
    """Raised when a browser session is invalid."""

    code = "INVALID_SESSION"
    message = "Invalid session"
    status = status.HTTP_401_UNAUTHORIZED
    headers: ClassVar[dict[str, str]] = {
        "WWW-Authenticate": "Session",
        **NO_STORE_HEADERS,
    }


class InvalidLoginCredentialsError(AppError):
    """Raised when login credentials are invalid."""

    code = "INVALID_LOGIN_CREDENTIALS"
    message = "Invalid email or password"
    status = status.HTTP_401_UNAUTHORIZED


class CSRFMissingCookieError(AppError):
    """Raised when a request does not carry the CSRF cookie."""

    code = "CSRF_MISSING_COOKIE"
    message = "CSRF cookie missing"
    status = status.HTTP_403_FORBIDDEN
    headers = NO_STORE_HEADERS


class CSRFMissingHeaderError(AppError):
    """Raised when a request does not carry the CSRF header."""

    code = "CSRF_MISSING_HEADER"
    message = "CSRF header missing"
    status = status.HTTP_403_FORBIDDEN
    headers = NO_STORE_HEADERS


class CSRFCookieHeaderMismatchError(AppError):
    """Raised when the CSRF cookie and header values differ."""

    code = "CSRF_COOKIE_HEADER_MISMATCH"
    message = "CSRF cookie header mismatch"
    status = status.HTTP_403_FORBIDDEN
    headers = NO_STORE_HEADERS


class CSRFRequestSourceMissingError(AppError):
    """Raised when an unsafe request has no Origin or Referer."""

    code = "CSRF_REQUEST_SOURCE_MISSING"
    message = "CSRF request source missing"
    status = status.HTTP_403_FORBIDDEN
    headers = NO_STORE_HEADERS


class CSRFRequestSourceUntrustedError(AppError):
    """Raised when an unsafe request comes from an untrusted source."""

    code = "CSRF_REQUEST_SOURCE_UNTRUSTED"
    message = "CSRF request source untrusted"
    status = status.HTTP_403_FORBIDDEN
    headers = NO_STORE_HEADERS


class CSRFFormOriginMismatchError(AppError):
    """Raised when a form's Origin or Referer is rejected."""

    code = "CSRF_FORM_ORIGIN_MISMATCH"
    message = "CSRF form origin mismatch"
    status = status.HTTP_403_FORBIDDEN
    headers = NO_STORE_HEADERS


class CSRFHeaderSessionMismatchError(AppError):
    """Raised when the CSRF header does not match the browser session."""

    code = "CSRF_HEADER_SESSION_MISMATCH"
    message = "CSRF header session mismatch"
    status = status.HTTP_403_FORBIDDEN
    headers = NO_STORE_HEADERS


CSRF_ERRORS: tuple[type[AppError], ...] = (
    CSRFMissingCookieError,
    CSRFMissingHeaderError,
    CSRFCookieHeaderMismatchError,
    CSRFRequestSourceMissingError,
    CSRFRequestSourceUntrustedError,
    CSRFHeaderSessionMismatchError,
)
