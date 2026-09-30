"""Canonical-server API version 1 composition."""

from fastapi import APIRouter

from app.api.error_responses import app_error_responses
from app.api.v1.auth.router import create_auth_router
from app.api.v1.browser_sessions.router import router as session_router
from app.api.v1.me.router import create_me_router
from app.api.v1.oauth2_interactions.router import create_oauth2_interaction_router
from app.api.v1.organization.router import create_organization_router
from app.api.v1.server.router import create_server_router
from app.db.errors import DatabaseBusyError
from app.http_paths import API_V1_PREFIX, BROWSER_SESSION_PREFIX
from app.settings.root import Settings


def include_v1_routes(router: APIRouter, settings: Settings) -> None:
    """Include identity APIs according to the immutable startup policy."""
    v1_router = APIRouter(
        responses=app_error_responses(
            DatabaseBusyError,
            descriptions={503: "SQLite is temporarily busy; retry the request."},
        )
    )
    v1_router.include_router(create_me_router(settings))
    if (
        settings.browser_session.enabled
        and settings.api.interactive_auth_routes_enabled
    ):
        v1_router.include_router(session_router, prefix=BROWSER_SESSION_PREFIX)
    if settings.api.interactive_auth_routes_enabled:
        v1_router.include_router(create_auth_router(settings), prefix="/auth")
    if (
        settings.api.interactive_auth_routes_enabled
        and settings.ui.oauth2_interaction_is_external
    ):
        v1_router.include_router(
            create_oauth2_interaction_router(
                authorization_code_enabled=settings.oauth2.authorization_code_enabled,
                device_code_enabled=settings.oauth2.device_code_enabled,
            ),
            prefix="/oauth2",
        )
    v1_router.include_router(create_organization_router(settings))
    v1_router.include_router(create_server_router(settings), prefix="/server")
    router.include_router(v1_router, prefix=API_V1_PREFIX)
