"""Compose current-user routes according to enabled server features."""

from fastapi import APIRouter, Depends

from app.api.dependencies.cache_control import prevent_authenticated_response_storage
from app.api.v1.me.oauth2_sessions import router as oauth2_session_router
from app.api.v1.me.profile import (
    browser_account_router,
    router as profile_router,
)
from app.api.v1.me.sessions import router as session_router
from app.settings.root import Settings


def create_me_router(settings: Settings) -> APIRouter:
    """Create the current-user router for the immutable startup policy."""
    router = APIRouter(dependencies=[Depends(prevent_authenticated_response_storage)])
    router.include_router(profile_router, prefix="/me")
    if settings.browser_session.enabled:
        router.include_router(browser_account_router, prefix="/me")
        router.include_router(session_router, prefix="/me")
        if settings.oauth2.has_enabled_grants:
            router.include_router(oauth2_session_router, prefix="/me")
    return router
