"""Compose versioned authentication workflow routes."""

from fastapi import APIRouter

from app.api.v1.auth.email_change import router as email_change_router
from app.api.v1.auth.email_verification import (
    confirmation_router as email_verification_confirmation_router,
    request_router as email_verification_request_router,
)
from app.api.v1.auth.invitations import router as invitations_router
from app.api.v1.auth.password_recovery import router as password_recovery_router
from app.api.v1.auth.registration import router as registration_router
from app.settings.root import Settings


def create_auth_router(settings: Settings) -> APIRouter:
    """Compose public authentication workflows from the startup policy."""
    router = APIRouter()
    if settings.auth.registration_enabled:
        router.include_router(registration_router)
        router.include_router(email_verification_request_router)
    router.include_router(email_verification_confirmation_router)
    router.include_router(email_change_router)
    router.include_router(password_recovery_router)
    router.include_router(invitations_router)
    return router
