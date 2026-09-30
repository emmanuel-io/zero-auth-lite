"""Transport-aware HTTP policy composed by the canonical application."""

from collections.abc import Awaitable, Callable
from typing import cast, TYPE_CHECKING

from fastapi import FastAPI, Request, Response
from fastapi.exceptions import RequestValidationError
from starlette.exceptions import HTTPException as StarletteHTTPException

from app.browser_sessions.enums import CSRFTokenExposure
from app.core.errors.base import AppError
from app.core.errors.handlers import (
    app_error_handler,
    http_error_handler,
    unexpected_error_handler,
    validation_error_handler,
)
from app.settings.root import Settings
from app.web.errors import (
    browser_app_error_handler,
    browser_http_error_handler,
    browser_unexpected_error_handler,
    browser_validation_error_handler,
)
from app.web.management.errors import (
    management_app_error_handler,
    management_http_error_handler,
    management_unexpected_error_handler,
    management_validation_error_handler,
)
from app.web.routes import browser_route, ManagementPageRoute


if TYPE_CHECKING:
    from starlette.types import ExceptionHandler


type ErrorHandler[ErrorT: Exception] = Callable[[Request, ErrorT], Awaitable[Response]]


def _include_cors_header(
    headers: tuple[str, ...], required_header: str
) -> tuple[str, ...]:
    """Include one required header while preserving configured order and casing."""
    if any(header.casefold() == required_header.casefold() for header in headers):
        return headers
    return (*headers, required_header)


def effective_cors_headers(
    settings: Settings,
) -> tuple[tuple[str, ...], tuple[str, ...]]:
    """Derive CORS request and exposure headers required by session CSRF."""
    allow_headers = settings.cors.allow_headers
    expose_headers = settings.cors.expose_headers
    if not settings.browser_session.enabled:
        return allow_headers, expose_headers

    csrf_settings = settings.browser_session.csrf
    allow_headers = _include_cors_header(allow_headers, csrf_settings.header_name)
    if csrf_settings.expose_token == CSRFTokenExposure.HEADER:
        expose_headers = _include_cors_header(
            expose_headers,
            csrf_settings.header_name,
        )
    return allow_headers, expose_headers


def _route_error_handler[ErrorT: Exception](
    request: Request,
    *,
    management_handler: ErrorHandler[ErrorT],
    browser_handler: ErrorHandler[ErrorT],
    api_handler: ErrorHandler[ErrorT],
) -> ErrorHandler[ErrorT]:
    """Select an error handler from the resolved route's transport surface."""
    route = browser_route(request)
    if isinstance(route, ManagementPageRoute):
        return management_handler
    if route is not None:
        return browser_handler
    return api_handler


def add_exception_handlers(app: FastAPI) -> None:
    """Register transport-aware handlers without coupling them to URL prefixes."""

    async def dispatch_app_error(request: Request, exc: AppError) -> Response:
        handler = _route_error_handler(
            request,
            management_handler=management_app_error_handler,
            browser_handler=browser_app_error_handler,
            api_handler=app_error_handler,
        )
        return await handler(request, exc)

    async def dispatch_validation_error(
        request: Request, exc: RequestValidationError
    ) -> Response:
        handler = _route_error_handler(
            request,
            management_handler=management_validation_error_handler,
            browser_handler=browser_validation_error_handler,
            api_handler=validation_error_handler,
        )
        return await handler(request, exc)

    async def dispatch_http_error(
        request: Request, exc: StarletteHTTPException
    ) -> Response:
        handler = _route_error_handler(
            request,
            management_handler=management_http_error_handler,
            browser_handler=browser_http_error_handler,
            api_handler=http_error_handler,
        )
        return await handler(request, exc)

    async def dispatch_unexpected_error(request: Request, exc: Exception) -> Response:
        handler = _route_error_handler(
            request,
            management_handler=management_unexpected_error_handler,
            browser_handler=browser_unexpected_error_handler,
            api_handler=unexpected_error_handler,
        )
        return await handler(request, exc)

    app.add_exception_handler(AppError, cast("ExceptionHandler", dispatch_app_error))
    app.add_exception_handler(
        StarletteHTTPException, cast("ExceptionHandler", dispatch_http_error)
    )
    app.add_exception_handler(
        RequestValidationError, cast("ExceptionHandler", dispatch_validation_error)
    )
    app.add_exception_handler(
        Exception, cast("ExceptionHandler", dispatch_unexpected_error)
    )
