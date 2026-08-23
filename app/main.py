"""Canonical FastAPI application for Zero Auth Lite."""

from __future__ import annotations

import logging
from typing import cast, TYPE_CHECKING

from asgi_correlation_id import CorrelationIdMiddleware
from fastapi import APIRouter, FastAPI
from fastapi.exceptions import RequestValidationError
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.middleware.cors import CORSMiddleware
from starlette.middleware.trustedhost import TrustedHostMiddleware
from starlette.staticfiles import StaticFiles

from app.api.router import create_api_router
from app.browser_sessions.enums import CSRFTokenExposure
from app.browser_sessions.response_transport import SessionResponseTransportMiddleware
from app.core.errors.base import AppError
from app.core.errors.handlers import (
    app_error_handler,
    http_error_handler,
    unexpected_error_handler,
    validation_error_handler,
)
from app.core.lifespan import lifespan
from app.core.logs.config import configure_logging as configure_root_logging
from app.core.logs.correlation import (
    generate_correlation_id,
    normalize_correlation_id,
)
from app.core.logs.middleware import RequestLoggingMiddleware
from app.oauth2.error_handler import oauth2_protocol_error_handler
from app.oauth2.errors import OAuth2ProtocolError
from app.oauth2.openapi import configure_oauth2_openapi
from app.oauth2.router import create_oauth2_router
from app.openapi_tags import create_openapi_tags, HEALTH_TAG
from app.password.pwdlib_hasher import PwdlibPasswordHasher
from app.settings.root import load_settings, Settings
from app.settings.state import set_settings_snapshot
from app.web.rendering import STATIC_DIR
from app.web.router import create_web_router


if TYPE_CHECKING:
    from starlette.types import ExceptionHandler


description = """
## Zero Auth Lite

Zero Auth Lite is a readable FastAPI authentication server with sessions, OAuth2,
OIDC, CSRF protection, transactional email flows, and explicit configuration.
"""

logger = logging.getLogger(__name__)

health_router = APIRouter()


def _include_cors_header(
    headers: tuple[str, ...], required_header: str
) -> tuple[str, ...]:
    """Include one required header while preserving configured order and casing."""
    if any(header.casefold() == required_header.casefold() for header in headers):
        return headers
    return (*headers, required_header)


def _effective_cors_headers(
    settings: Settings,
) -> tuple[tuple[str, ...], tuple[str, ...]]:
    """Derive CORS request and exposure headers required by session CSRF."""
    allow_headers = settings.cors.allow_headers
    expose_headers = settings.cors.expose_headers
    if not settings.session.enabled:
        return allow_headers, expose_headers

    csrf_settings = settings.session.csrf
    allow_headers = _include_cors_header(allow_headers, csrf_settings.header_name)
    if csrf_settings.expose_token == CSRFTokenExposure.HEADER:
        expose_headers = _include_cors_header(
            expose_headers,
            csrf_settings.header_name,
        )
    return allow_headers, expose_headers


@health_router.get("/health", tags=[HEALTH_TAG])
async def health() -> dict[str, str]:
    """Return a minimal health response for local smoke checks."""
    return {"status": "ok"}


def create_app(
    settings: Settings | None = None, *, configure_app_logging: bool = True
) -> FastAPI:
    """Create the canonical server from one immutable settings snapshot.

    Set ``configure_app_logging`` to false when embedding Zero Auth Lite in a
    process whose root logging handlers are owned by the host application.
    """
    if settings is None:
        settings = load_settings()
    if configure_app_logging:
        configure_root_logging(settings.app.log_level)

    openapi_tags = create_openapi_tags(settings)

    app = FastAPI(
        title="Zero Auth Lite",
        summary=(
            "Canonical FastAPI server for Zero Auth Lite sessions, OAuth2, and OIDC."
        ),
        description=description,
        openapi_url="/api/docs/openapi.json",
        docs_url="/api/docs",
        redoc_url="/api/redocs",
        version="0.1.0",
        lifespan=lifespan,
        openapi_tags=openapi_tags,
    )
    set_settings_snapshot(app, settings)
    app.state.password_hasher = PwdlibPasswordHasher()

    if settings.session.enabled:
        app.add_middleware(
            SessionResponseTransportMiddleware,
            csrf_settings=settings.session.csrf,
            session_settings=settings.session,
        )

    if settings.cors.enabled:
        allow_headers, expose_headers = _effective_cors_headers(settings)
        logger.info("Enabling CORS for origins: %s", settings.cors.allowed_origins)
        app.add_middleware(
            CORSMiddleware,
            allow_origins=settings.cors.allowed_origins,
            allow_credentials=settings.cors.allow_credentials,
            allow_methods=settings.cors.allow_methods,
            allow_headers=allow_headers,
            expose_headers=expose_headers,
        )
    if settings.app.trusted_hosts:
        logger.info("Enabling trusted host checks: %s", settings.app.trusted_hosts)
        app.add_middleware(
            TrustedHostMiddleware,
            allowed_hosts=settings.app.trusted_hosts,
        )
    logger.info("Adding request logging middleware")
    app.add_middleware(RequestLoggingMiddleware)
    logger.info("Adding correlation ID middleware")
    app.add_middleware(
        CorrelationIdMiddleware,
        generator=generate_correlation_id,
        transformer=normalize_correlation_id,
    )

    app.add_exception_handler(AppError, cast("ExceptionHandler", app_error_handler))
    app.add_exception_handler(
        StarletteHTTPException, cast("ExceptionHandler", http_error_handler)
    )
    app.add_exception_handler(
        RequestValidationError, cast("ExceptionHandler", validation_error_handler)
    )
    app.add_exception_handler(
        Exception, cast("ExceptionHandler", unexpected_error_handler)
    )

    if settings.oauth2.protocol_enabled:
        app.add_exception_handler(
            OAuth2ProtocolError,
            cast("ExceptionHandler", oauth2_protocol_error_handler),
        )
        logger.info("Including OAuth2/OIDC routes")
        app.include_router(create_oauth2_router(settings))

    app.include_router(health_router)

    if (
        settings.ui.oauth2_interaction_is_builtin
        or settings.ui.authentication_is_builtin
    ):
        logger.info("Including built-in browser UI")
        app.mount("/static", StaticFiles(directory=STATIC_DIR), name="web-static")
        app.include_router(create_web_router(settings))
    logger.info("Including versioned canonical server API routes")
    app.include_router(create_api_router(settings), prefix="/api")
    configure_oauth2_openapi(app)

    return app
