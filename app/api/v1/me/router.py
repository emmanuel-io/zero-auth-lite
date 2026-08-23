"""Compose current-user routes according to enabled server features."""

from fastapi import APIRouter

from app.api.v1.me.authorizations import router as authorization_router
from app.api.v1.me.profile import router as profile_router
from app.api.v1.me.sessions import router as session_router
from app.settings.root import Settings


def create_me_router(settings: Settings) -> APIRouter:
    """Create the current-user router for the immutable startup policy."""
    router = APIRouter()
    router.include_router(profile_router, prefix="/me")
    if settings.session.enabled:
        router.include_router(session_router, prefix="/me")
        if settings.oauth2.has_enabled_grants:
            router.include_router(authorization_router, prefix="/me")
    return router
