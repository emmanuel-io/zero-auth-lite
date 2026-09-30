"""Composition for server-operator OAuth2 client browser routes."""

from fastapi import APIRouter

from app.web.management.operator.oauth2_clients.access import router as access_router
from app.web.management.operator.oauth2_clients.credentials import (
    router as credentials_router,
)
from app.web.management.operator.oauth2_clients.deletion import (
    router as deletion_router,
)
from app.web.management.operator.oauth2_clients.registry import (
    router as registry_router,
)


router = APIRouter()
router.include_router(registry_router)
router.include_router(access_router)
router.include_router(credentials_router)
router.include_router(deletion_router)
