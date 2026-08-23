"""Canonical-server API version 1 composition."""

from fastapi import APIRouter

from app.api.v1.admin.router import create_admin_router
from app.api.v1.auth.router import create_auth_router
from app.api.v1.browser_sessions.router import router as session_router
from app.api.v1.me.router import create_me_router
from app.api.v1.organization.router import create_organization_router
from app.settings.root import Settings


def include_v1_routes(router: APIRouter, settings: Settings) -> None:
    """Include identity APIs according to the immutable startup policy."""
    v1_router = APIRouter()
    v1_router.include_router(create_me_router(settings))
    if settings.session.enabled and not settings.ui.authentication_is_builtin:
        v1_router.include_router(session_router, prefix="/sessions")
    v1_router.include_router(create_organization_router(settings))
    v1_router.include_router(create_admin_router(settings), prefix="/admin")
    router.include_router(v1_router, prefix="/v1")
    if not settings.ui.authentication_is_builtin:
        router.include_router(create_auth_router(settings), prefix="/v1/auth")
