"""Session-backed management dashboard."""

from fastapi import Request, Response

from app.browser_sessions.dependencies import (
    CurrentBrowserUserContextDep,
)
from app.browser_sessions.service_dependencies import BrowserSessionLifecycleServiceDep
from app.settings.dependencies import SettingsDep
from app.web.management.responses import render_management_page


async def management_dashboard(
    request: Request,
    lifecycle_service: BrowserSessionLifecycleServiceDep,
    user_ctx: CurrentBrowserUserContextDep,
    settings: SettingsDep,
) -> Response:
    """Show the authenticated user's available management destinations."""
    return await render_management_page(
        request,
        lifecycle_service,
        user_ctx,
        "management/dashboard.html",
        application_url=(
            str(settings.default_redirect_url)
            if settings.default_redirect_url is not None
            else None
        ),
        show_api_docs=settings.app.environment == "development",
    )
