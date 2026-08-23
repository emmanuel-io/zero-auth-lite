"""Settings-driven composition for the canonical OAuth2/OIDC route surface."""

from fastapi import APIRouter

from app.oauth2.authorization.router import router as oauth2_authorize_router
from app.oauth2.devices.router import router as oauth2_device_router
from app.oauth2.oidc.router import (
    create_oidc_discovery_router,
    router as oidc_router,
)
from app.oauth2.routers.discovery import create_oauth_metadata_router
from app.oauth2.routers.jwks import router as oauth2_jwks_router
from app.oauth2.routers.tokens import router as oauth2_token_router
from app.settings.root import Settings


def create_oauth2_router(settings: Settings) -> APIRouter:
    """Create the canonical OAuth2 and OIDC route surface for enabled features."""
    router = APIRouter()
    if not settings.oauth2.protocol_enabled:
        return router
    protocol_router = APIRouter(prefix="/oauth2")

    router.include_router(create_oauth_metadata_router(settings.oauth2))
    if settings.oauth2.oidc_enabled:
        router.include_router(create_oidc_discovery_router(settings))
    if settings.oauth2.authorization_code_enabled:
        protocol_router.include_router(oauth2_authorize_router)
    if settings.oauth2.has_enabled_grants:
        protocol_router.include_router(oauth2_token_router)
    if settings.oauth2.device_code_enabled:
        protocol_router.include_router(oauth2_device_router)
    if settings.oauth2.jwks_enabled:
        protocol_router.include_router(oauth2_jwks_router)
    if settings.oauth2.oidc_enabled:
        protocol_router.include_router(oidc_router)
    router.include_router(protocol_router)

    return router
