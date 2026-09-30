"""Settings-driven composition for management browser routes."""

from fastapi import APIRouter, HTTPException, status

from app.openapi_tags import MANAGEMENT_UI_TAG
from app.settings.root import Settings
from app.web.management.account import router as account_router
from app.web.management.dashboard import management_dashboard
from app.web.management.operator import create_operator_ui_router
from app.web.management.organization import create_organization_ui_router
from app.web.routes import ManagementPageRoute


async def management_page_not_found(unmatched_path: str) -> None:
    """Raise an HTML-classified 404 for an unmatched management URL."""
    del unmatched_path
    raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Not Found")


def create_management_ui_router(settings: Settings) -> APIRouter:
    """Compose account pages and independently toggled administration pages."""
    router = APIRouter(prefix="/management")
    router.add_api_route(
        "",
        management_dashboard,
        methods=["GET"],
        tags=[MANAGEMENT_UI_TAG],
        route_class_override=ManagementPageRoute,
    )
    router.include_router(account_router, prefix="/account")
    if settings.ui.organization_admin_enabled:
        router.include_router(create_organization_ui_router(settings))
    if settings.ui.operator_enabled:
        router.include_router(create_operator_ui_router(settings))
    router.add_api_route(
        "/{unmatched_path:path}",
        management_page_not_found,
        methods=["GET", "POST"],
        include_in_schema=False,
        route_class_override=ManagementPageRoute,
    )
    return router
