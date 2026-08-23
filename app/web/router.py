"""Settings-driven composition for built-in browser presentation."""

from fastapi import APIRouter

from app.settings.root import Settings
from app.web.auth.consent import router as consent_router
from app.web.auth.device import router as device_router
from app.web.auth.email import router as email_router
from app.web.auth.login import router as login_router
from app.web.auth.workflows import create_auth_workflow_router
from app.web.landing import router as landing_router


def create_web_router(settings: Settings) -> APIRouter:
    """Compose browser pages for enabled canonical-server capabilities."""
    router = APIRouter()
    if settings.ui.authentication_is_builtin:
        router.include_router(landing_router)
        router.include_router(email_router)
        router.include_router(create_auth_workflow_router(settings))
        if settings.session.enabled:
            router.include_router(login_router)
    if (
        settings.ui.oauth2_interaction_is_builtin
        and settings.oauth2.authorization_code_enabled
    ):
        router.include_router(consent_router)
    if settings.oauth2.device_code_enabled:
        router.include_router(device_router)
    return router
