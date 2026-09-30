"""Settings-driven composition for authentication browser routes."""

from fastapi import APIRouter

from app.settings.root import Settings
from app.web.auth.consent import router as consent_router
from app.web.auth.device import router as device_router
from app.web.auth.email import router as email_router
from app.web.auth.login import router as login_router
from app.web.auth.workflows import create_identity_workflow_router, session_router
from app.web.composition import (
    builtin_identity_workflows_enabled,
    builtin_landing_enabled,
    builtin_login_enabled,
    builtin_management_authentication_enabled,
)
from app.web.landing import router as landing_router


def create_authentication_ui_router(settings: Settings) -> APIRouter:
    """Compose native-form authentication and OAuth2 interaction pages."""
    router = APIRouter()
    if builtin_landing_enabled(settings):
        router.include_router(landing_router)
    if builtin_identity_workflows_enabled(settings):
        router.include_router(email_router)
        router.include_router(create_identity_workflow_router(settings))
    if builtin_login_enabled(settings):
        router.include_router(login_router)
    if builtin_management_authentication_enabled(settings):
        router.include_router(session_router)
    if (
        settings.ui.oauth2_interaction_is_builtin
        and settings.oauth2.authorization_code_enabled
    ):
        router.include_router(consent_router)
    if (
        settings.ui.oauth2_interaction_is_builtin
        and settings.oauth2.device_code_enabled
    ):
        router.include_router(device_router)
    return router
