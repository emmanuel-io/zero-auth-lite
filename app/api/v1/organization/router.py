"""Compose current-organization administration routes."""

from fastapi import APIRouter

from app.api.v1.organization.metadata import router as organization_metadata_router
from app.api.v1.organization.oauth2_sessions.router import (
    router as oauth2_sessions_router,
)
from app.api.v1.organization.users.router import router as users_router
from app.settings.root import Settings


def create_organization_router(settings: Settings) -> APIRouter:
    """Create the current-organization administration surface."""
    router = APIRouter()
    router.include_router(organization_metadata_router, prefix="/organization")
    router.include_router(users_router, prefix="/organization")
    if settings.oauth2.has_enabled_grants:
        router.include_router(oauth2_sessions_router, prefix="/organization")
    return router
