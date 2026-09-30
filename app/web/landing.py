"""Minimal landing page for standalone interactive authentication."""

from fastapi import APIRouter, Request, Response

from app.browser_sessions.dependencies import PublicOptionalBrowserUserContextDep
from app.openapi_tags import BUILTIN_AUTH_UI_TAG
from app.settings.dependencies import SettingsDep
from app.web.redirects import management_authentication_entry_url
from app.web.rendering import no_store_redirect, render_page
from app.web.routes import BrowserPageRoute


router = APIRouter(tags=[BUILTIN_AUTH_UI_TAG], route_class=BrowserPageRoute)


@router.get("/")
async def landing_page(
    request: Request,
    user_ctx: PublicOptionalBrowserUserContextDep,
    settings: SettingsDep,
) -> Response:
    """Render the standalone entry point without application behavior."""
    if user_ctx is not None:
        return no_store_redirect("/management")
    return render_page(
        request,
        "landing.html",
        sign_in_url=(
            management_authentication_entry_url(settings)
            if settings.browser_session.enabled
            else None
        ),
        application_url=(
            str(settings.default_redirect_url)
            if settings.default_redirect_url is not None
            else None
        ),
        show_api_docs=settings.app.environment == "development",
    )
