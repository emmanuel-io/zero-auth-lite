"""Minimal landing page for standalone interactive authentication."""

from fastapi import APIRouter, Request
from starlette.responses import HTMLResponse

from app.browser_sessions.dependencies import PublicOptionalBrowserUserContextDep
from app.openapi_tags import BUILTIN_AUTH_UI_TAG
from app.settings.dependencies import SettingsDep
from app.web.rendering import render_page


router = APIRouter(tags=[BUILTIN_AUTH_UI_TAG])


@router.get("/")
async def landing_page(
    request: Request,
    user_ctx: PublicOptionalBrowserUserContextDep,
    settings: SettingsDep,
) -> HTMLResponse:
    """Render the standalone entry point without application behavior."""
    return render_page(
        request,
        "landing.html",
        authenticated=user_ctx is not None,
        sign_in_enabled=settings.session.enabled,
        application_url=(
            str(settings.default_redirect_url)
            if settings.default_redirect_url is not None
            else None
        ),
        show_api_docs=settings.app.environment == "development",
    )
