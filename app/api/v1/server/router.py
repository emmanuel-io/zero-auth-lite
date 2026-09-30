"""Composition for server-wide control-plane routes."""

from fastapi import APIRouter, Depends

from app.api.dependencies.cache_control import prevent_authenticated_response_storage
from app.api.v1.server.browser_sessions import router as browser_sessions_router
from app.api.v1.server.oauth2_clients.router import router as oauth2_clients_router
from app.api.v1.server.organizations.router import router as organizations_router
from app.api.v1.server.organizations.security_sessions import (
    router as organization_security_sessions_router,
)
from app.api.v1.server.users.router import router as users_router
from app.openapi_tags import SERVER_CONTROL_PLANE_V1_TAG
from app.settings.root import Settings


router = APIRouter(tags=[SERVER_CONTROL_PLANE_V1_TAG])
router.include_router(organizations_router)
router.include_router(organization_security_sessions_router)
router.include_router(users_router)


def create_server_router(settings: Settings) -> APIRouter:
    """Compose server control-plane routes for enabled features."""
    composed_router = APIRouter(
        dependencies=[Depends(prevent_authenticated_response_storage)]
    )
    composed_router.include_router(router)
    if settings.oauth2.has_enabled_grants:
        composed_router.include_router(
            oauth2_clients_router,
            tags=[SERVER_CONTROL_PLANE_V1_TAG],
        )
    if settings.browser_session.enabled:
        composed_router.include_router(
            browser_sessions_router,
            tags=[SERVER_CONTROL_PLANE_V1_TAG],
        )
    return composed_router
