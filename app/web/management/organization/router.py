"""Composition for organization-administrator browser routes."""

from fastapi import APIRouter

from app.openapi_tags import ORGANIZATION_ADMINISTRATION_UI_TAG
from app.settings.root import Settings
from app.web.management.organization.metadata import create_metadata_router
from app.web.management.organization.oauth2_sessions import (
    router as oauth2_sessions_router,
)
from app.web.management.organization.security_sessions import (
    router as security_sessions_router,
)
from app.web.management.organization.user_sessions import (
    router as user_sessions_router,
)
from app.web.management.organization.users import router as users_router
from app.web.routes import ManagementPageRoute


def create_organization_ui_router(settings: Settings) -> APIRouter:
    """Compose organization routes for the server's enabled capabilities."""
    router = APIRouter(
        tags=[ORGANIZATION_ADMINISTRATION_UI_TAG], route_class=ManagementPageRoute
    )
    router.include_router(create_metadata_router(settings), prefix="/organization")
    router.include_router(users_router, prefix="/organization")
    router.include_router(user_sessions_router, prefix="/organization")
    router.include_router(security_sessions_router, prefix="/organization")
    if settings.oauth2.has_enabled_grants:
        router.include_router(oauth2_sessions_router, prefix="/organization")
    return router
