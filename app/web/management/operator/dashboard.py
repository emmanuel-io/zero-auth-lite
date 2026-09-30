"""Server-operator dashboard route."""

from typing import Annotated

from fastapi import APIRouter, Query, Request, Response

from app.browser_sessions.service_dependencies import BrowserSessionLifecycleServiceDep
from app.settings.root import Settings
from app.web.management.dependencies import OperatorUIDep
from app.web.management.responses import render_management_page
from app.web.routes import ManagementPageRoute


def create_dashboard_router(settings: Settings) -> APIRouter:
    """Create the operator dashboard route."""
    router = APIRouter(route_class=ManagementPageRoute)

    @router.get("")
    async def dashboard(
        request: Request,
        lifecycle_service: BrowserSessionLifecycleServiceDep,
        user_ctx: OperatorUIDep,
        notice: Annotated[str | None, Query()] = None,
    ) -> Response:
        """Render the management dashboard."""
        return await render_management_page(
            request,
            lifecycle_service,
            user_ctx,
            "management/operator/dashboard.html",
            oauth2_enabled=settings.oauth2.has_enabled_grants,
            notice=notice,
        )

    return router
