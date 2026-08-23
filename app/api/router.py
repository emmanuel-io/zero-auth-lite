"""Canonical-server application API top-level router factory."""

from fastapi import APIRouter

from app.api.v1.router import include_v1_routes
from app.settings.root import Settings


def create_api_router(settings: Settings) -> APIRouter:
    """Create the canonical-server application API router."""
    router = APIRouter()
    include_v1_routes(router, settings)
    return router
