"""Canonical FastAPI application for Zero Auth Lite."""

from __future__ import annotations

import logging
from typing import cast, TYPE_CHECKING

from asgi_correlation_id import CorrelationIdMiddleware
from fastapi import FastAPI
from starlette.middleware.cors import CORSMiddleware
from starlette.middleware.trustedhost import TrustedHostMiddleware
from starlette.staticfiles import StaticFiles

from app.api.router import create_api_router
from app.browser_sessions.response_transport import (
    BrowserSessionResponseTransportMiddleware,
)
from app.core.logs.config import configure_logging as configure_root_logging
from app.core.logs.correlation import (
    generate_correlation_id,
    normalize_correlation_id,
)
from app.core.logs.middleware import RequestLoggingMiddleware
from app.health.router import router as health_router
from app.http_composition import add_exception_handlers, effective_cors_headers
from app.http_paths import API_PREFIX
from app.lifespan import lifespan
from app.oauth2.error_handler import oauth2_protocol_error_handler
from app.oauth2.errors import OAuth2ProtocolError
from app.oauth2.router import create_oauth2_router
from app.openapi import configure_openapi
from app.openapi_tags import create_openapi_tags
from app.password.pwdlib_hasher import PwdlibPasswordHasher
from app.settings.root import load_settings, Settings
from app.settings.state import set_settings_snapshot
from app.version import get_application_version
from app.web.composition import authentication_ui_enabled, management_ui_enabled
from app.web.rendering import STATIC_DIR
from app.web.router import create_web_router


if TYPE_CHECKING:
    from starlette.types import ExceptionHandler


description = """
## Zero Auth Lite

Zero Auth Lite is a readable FastAPI authentication server with sessions, OAuth2,
OIDC, CSRF protection, authentication email flows, and explicit configuration.
"""

logger = logging.getLogger(__name__)


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
        version=get_application_version(),
        lifespan=lifespan,
        openapi_tags=openapi_tags,
    )
    set_settings_snapshot(app, settings)
    app.state.password_hasher = PwdlibPasswordHasher()

    if settings.browser_session.enabled:
        app.add_middleware(
            BrowserSessionResponseTransportMiddleware,
            csrf_settings=settings.browser_session.csrf,
            session_settings=settings.browser_session,
        )

    if settings.cors.allowed_origins:
        allow_headers, expose_headers = effective_cors_headers(settings)
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

    add_exception_handlers(app)

    if settings.oauth2.protocol_enabled:
        app.add_exception_handler(
            OAuth2ProtocolError,
            cast("ExceptionHandler", oauth2_protocol_error_handler),
        )
        logger.info("Including OAuth2/OIDC routes")
        app.include_router(create_oauth2_router(settings))

    app.include_router(health_router)

    has_authentication_ui = authentication_ui_enabled(settings)
    has_management_ui = management_ui_enabled(settings)
    if has_authentication_ui or has_management_ui:
        app.mount("/static", StaticFiles(directory=STATIC_DIR), name="web-static")
        if has_authentication_ui:
            logger.info("Including Authentication UI routes")
        if has_management_ui:
            logger.info("Including Management UI routes")
        app.include_router(create_web_router(settings))
    logger.info("Including versioned canonical server API routes")
    app.include_router(create_api_router(settings), prefix=API_PREFIX)
    configure_openapi(app)

    return app
