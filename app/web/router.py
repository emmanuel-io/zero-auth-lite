"""Settings-driven composition for built-in browser presentation."""

from fastapi import APIRouter

from app.settings.root import Settings
from app.web.auth.router import create_authentication_ui_router
from app.web.composition import authentication_ui_enabled, management_ui_enabled
from app.web.management.router import create_management_ui_router


def create_web_router(settings: Settings) -> APIRouter:
    """Compose browser pages for enabled canonical-server capabilities."""
    router = APIRouter()
    if authentication_ui_enabled(settings):
        router.include_router(create_authentication_ui_router(settings))
    if management_ui_enabled(settings):
        router.include_router(create_management_ui_router(settings))
    return router
