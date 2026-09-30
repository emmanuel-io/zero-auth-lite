"""HTML error translation for built-in browser pages."""

from logging import getLogger
from typing import TYPE_CHECKING

from fastapi import Request, status
from starlette.responses import HTMLResponse

from app.core.errors.base import AppError
from app.web.rendering import render_page


if TYPE_CHECKING:
    from fastapi.exceptions import RequestValidationError
    from starlette.exceptions import HTTPException as StarletteHTTPException


logger = getLogger(__name__)


def _error_page(
    request: Request,
    *,
    status_code: int,
    title: str,
    message: str,
) -> HTMLResponse:
    """Render a safe full-page browser error."""
    return render_page(
        request,
        "error.html",
        status_code=status_code,
        title=title,
        message=message,
        link_url=None,
        link_label=None,
    )


async def browser_app_error_handler(request: Request, exc: AppError) -> HTMLResponse:
    """Render an expected application failure for a browser page."""
    response = _error_page(
        request,
        status_code=exc.status,
        title="Request unavailable",
        message=exc.message,
    )
    response.headers.update(exc.headers)
    return response


async def browser_validation_error_handler(
    request: Request, exc: "RequestValidationError"
) -> HTMLResponse:
    """Render typed request validation failures without exposing raw values."""
    details = [str(error.get("msg", "Invalid value")) for error in exc.errors()]
    return _error_page(
        request,
        status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
        title="Check the submitted values",
        message=" ".join(details),
    )


async def browser_http_error_handler(
    request: Request, exc: "StarletteHTTPException"
) -> HTMLResponse:
    """Render framework HTTP failures for a resolved browser route."""
    status_code = getattr(exc, "status_code", status.HTTP_500_INTERNAL_SERVER_ERROR)
    detail = exc.detail
    message = detail if isinstance(detail, str) else "The request could not be handled."
    if status_code >= status.HTTP_500_INTERNAL_SERVER_ERROR:
        message = "Internal server error."
    response = _error_page(
        request,
        status_code=status_code,
        title="Request unavailable",
        message=message,
    )
    response.headers.update(getattr(exc, "headers", None) or {})
    return response


async def browser_unexpected_error_handler(
    request: Request, exc: Exception
) -> HTMLResponse:
    """Log an unexpected browser failure and return a non-sensitive page."""
    logger.error(
        "unexpected_browser_error",
        exc_info=exc,
        extra={"exception_type": type(exc).__name__},
    )
    return _error_page(
        request,
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        title="Request unavailable",
        message="Internal server error.",
    )
