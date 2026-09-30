"""Composition for server-operator browser routes."""

from fastapi import APIRouter

from app.openapi_tags import OPERATOR_UI_TAG
from app.settings.root import Settings
from app.web.management.operator.dashboard import create_dashboard_router
from app.web.management.operator.oauth2_clients import router as oauth2_clients_router
from app.web.management.operator.organization_sessions import (
    router as organization_sessions_router,
)
from app.web.management.operator.organizations import router as organizations_router
from app.web.management.operator.sessions import router as sessions_router
from app.web.management.operator.user_sessions import router as user_sessions_router
from app.web.management.operator.users import router as users_router
from app.web.routes import ManagementPageRoute


def create_operator_ui_router(settings: Settings) -> APIRouter:
    """Compose operator routes for the server's enabled capabilities."""
    router = APIRouter(tags=[OPERATOR_UI_TAG], route_class=ManagementPageRoute)
    router.include_router(create_dashboard_router(settings), prefix="/operator")
    router.include_router(organizations_router, prefix="/operator")
    router.include_router(organization_sessions_router, prefix="/operator")
    router.include_router(users_router, prefix="/operator")
    router.include_router(user_sessions_router, prefix="/operator")
    router.include_router(sessions_router, prefix="/operator")
    if settings.oauth2.has_enabled_grants:
        router.include_router(oauth2_clients_router, prefix="/operator")
    return router
