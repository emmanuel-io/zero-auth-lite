"""Composition for server-operator control-plane routes."""

from fastapi import APIRouter

from app.api.v1.admin.browser_sessions import router as browser_sessions_router
from app.api.v1.admin.oauth2_clients.router import router as oauth2_clients_router
from app.api.v1.admin.organizations.router import router as organizations_router
from app.api.v1.admin.organizations.security_sessions import (
    router as organization_security_sessions_router,
)
from app.api.v1.admin.users.router import router as users_router
from app.openapi_tags import SERVER_ADMINISTRATION_V1_TAG
from app.settings.root import Settings


router = APIRouter(tags=[SERVER_ADMINISTRATION_V1_TAG])
router.include_router(organizations_router)
router.include_router(organization_security_sessions_router)
router.include_router(users_router)


def create_admin_router(settings: Settings) -> APIRouter:
    """Compose server-operator routes for enabled features."""
    composed_router = APIRouter()
    composed_router.include_router(router)
    if settings.oauth2.has_enabled_grants:
        composed_router.include_router(
            oauth2_clients_router,
            tags=[SERVER_ADMINISTRATION_V1_TAG],
        )
    if settings.session.enabled:
        composed_router.include_router(
            browser_sessions_router,
            tags=[SERVER_ADMINISTRATION_V1_TAG],
        )
    return composed_router
