"""Compose server-operator OAuth2 client administration routes."""

from fastapi import APIRouter

from app.api.v1.admin.oauth2_clients.credentials import (
    router as credentials_router,
)
from app.api.v1.admin.oauth2_clients.machine_organizations import (
    router as machine_organizations_router,
)
from app.api.v1.admin.oauth2_clients.registry import (
    router as registry_router,
)
from app.api.v1.admin.oauth2_clients.user_organizations import (
    router as user_organizations_router,
)


router = APIRouter()
router.include_router(registry_router)
router.include_router(credentials_router)
router.include_router(user_organizations_router)
router.include_router(machine_organizations_router)
