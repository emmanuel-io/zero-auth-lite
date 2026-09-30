"""HTML error translation at the management route boundary."""

from logging import getLogger
from typing import NoReturn, TYPE_CHECKING

from fastapi import Request, status
from starlette.responses import Response

from app.browser_sessions.errors import BrowserSessionInvalidError
from app.core.errors.base import AppError
from app.core.errors.common import UnauthorizedError
from app.oauth2.clients.management.app_errors import (
    OAuth2ClientManagementAppError,
    raise_oauth2_client_management_error,
)
from app.oauth2.clients.management.errors import OAuth2ClientServiceError
from app.settings.state import get_settings_snapshot
from app.web.management.responses import full_navigation, management_shell_navigation
from app.web.redirects import management_authentication_entry_url
from app.web.rendering import render_page


if TYPE_CHECKING:
    from fastapi.exceptions import RequestValidationError
    from starlette.exceptions import HTTPException as StarletteHTTPException


logger = getLogger(__name__)


class ManagementStartDateAfterEndDateError(AppError):
    """Reject an inverted date range submitted to a management page."""

    code = "START_DATE_AFTER_END_DATE"
    message = "Start date is after end date."
    status = status.HTTP_400_BAD_REQUEST


def raise_management_oauth2_client_error(
    exc: OAuth2ClientServiceError,
) -> NoReturn:
    """Translate domain failures without depending on the JSON API adapter."""
    raise_oauth2_client_management_error(exc)


def _return_target(request: Request) -> str:
    """Preserve a same-origin management destination for post-login return."""
    query = request.url.query
    return f"{request.url.path}?{query}" if query else request.url.path


async def management_app_error_handler(request: Request, exc: AppError) -> Response:
    """Translate expected management failures into redirects or safe HTML."""
    if isinstance(exc, (UnauthorizedError, BrowserSessionInvalidError)):
        settings = get_settings_snapshot(request.app)
        return full_navigation(
            request,
            management_authentication_entry_url(
                settings,
                return_url=_return_target(request),
            ),
        )
    message = (
        exc.display_message
        if isinstance(exc, OAuth2ClientManagementAppError)
        else exc.message
    )
    return render_page(
        request,
        "management/error.html",
        status_code=exc.status,
        title="Request unavailable",
        message=message,
        fragment=request.headers.get("HX-Request", "").casefold() == "true",
        **management_shell_navigation(request),
    )


async def management_validation_error_handler(
    request: Request, exc: "RequestValidationError"
) -> Response:
    """Return typed form validation failures as an accessible HTML response."""
    details = [error.get("msg", "Invalid value") for error in exc.errors()]
    return render_page(
        request,
        "management/error.html",
        status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
        title="Check the submitted values",
        message=" ".join(str(detail) for detail in details),
        fragment=request.headers.get("HX-Request", "").casefold() == "true",
        **management_shell_navigation(request),
    )


async def management_http_error_handler(
    request: Request, exc: "StarletteHTTPException"
) -> Response:
    """Render framework HTTP failures as management HTML."""
    status_code = getattr(exc, "status_code", status.HTTP_500_INTERNAL_SERVER_ERROR)
    detail = exc.detail
    message = detail if isinstance(detail, str) else "The request could not be handled."
    if status_code >= status.HTTP_500_INTERNAL_SERVER_ERROR:
        message = "Internal server error."
    response = render_page(
        request,
        "management/error.html",
        status_code=status_code,
        title="Request unavailable",
        message=message,
        fragment=request.headers.get("HX-Request", "").casefold() == "true",
        **management_shell_navigation(request),
    )
    response.headers.update(getattr(exc, "headers", None) or {})
    return response


async def management_unexpected_error_handler(
    request: Request, exc: Exception
) -> Response:
    """Log an unexpected management failure and return safe HTML."""
    logger.error(
        "unexpected_management_error",
        exc_info=exc,
        extra={"exception_type": type(exc).__name__},
    )
    return render_page(
        request,
        "management/error.html",
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        title="Request unavailable",
        message="Internal server error.",
        fragment=request.headers.get("HX-Request", "").casefold() == "true",
        **management_shell_navigation(request),
    )
