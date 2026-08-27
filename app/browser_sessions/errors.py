"""Session authentication exceptions."""

from typing import ClassVar

from fastapi import status

from app.core.errors.base import AppError


class SessionInvalidError(AppError):
    """Handles Session validation errors."""

    code = "INVALID_SESSION"
    message = "Invalid session"
    status = status.HTTP_401_UNAUTHORIZED
    headers: ClassVar[dict[str, str]] = {"WWW-Authenticate": "Session"}


class InvalidLoginCredentialsError(AppError):
    """Handles invalid login credential errors."""

    code = "INVALID_LOGIN_CREDENTIALS"
    message = "Invalid email or password"
    status = status.HTTP_401_UNAUTHORIZED


class CSRFMissingCookieError(AppError):
    """Handles missing csrf cookie errors."""

    code = "CSRF_MISSING_COOKIE"
    message = "CSRF cookie missing"
    status = status.HTTP_403_FORBIDDEN


class CSRFMissingHeaderError(AppError):
    """Handles missing csrf header errors."""

    code = "CSRF_MISSING_HEADER"
    message = "CSRF header missing"
    status = status.HTTP_403_FORBIDDEN


class CSRFCookieHeaderMismatchError(AppError):
    """Handles csrf cookie header mismatch errors."""

    code = "CSRF_COOKIE_HEADER_MISMATCH"
    message = "CSRF cookie header mismatch"
    status = status.HTTP_403_FORBIDDEN


class CSRFFormOriginMismatchError(AppError):
    """Handles a rejected Origin or Referer on a server-rendered form."""

    code = "CSRF_FORM_ORIGIN_MISMATCH"
    message = "CSRF form origin mismatch"
    status = status.HTTP_403_FORBIDDEN


class CSRFHeaderSessionMismatchError(AppError):
    """Handles csrf header session mismatch errors."""

    code = "CSRF_HEADER_SESSION_MISMATCH"
    message = "CSRF header session mismatch"
    status = status.HTTP_403_FORBIDDEN
