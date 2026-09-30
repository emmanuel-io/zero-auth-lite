"""Server-rendered OAuth2 consent continuation page."""

from typing import Annotated

from fastapi import APIRouter, Query, Request, Response, status
from starlette.responses import HTMLResponse

from app.browser_sessions.dependencies import (
    PublicOptionalBrowserUserContextDep,
)
from app.browser_sessions.service_dependencies import BrowserSessionLifecycleServiceDep
from app.oauth2.authorization.http import (
    authorization_interaction_entry_url,
    authorization_response,
)
from app.oauth2.authorization.interaction import (
    AuthorizationInteractionServiceDep,
)
from app.oauth2.authorization.result import AuthorizationRedirect
from app.openapi_tags import OAUTH2_AUTHORIZATION_CODE_FLOW_TAG
from app.settings.dependencies import SettingsDep
from app.settings.ui import BUILTIN_AUTHORIZATION_CONSENT_PATH
from app.web.rendering import no_store_redirect, render_page
from app.web.routes import BrowserPageRoute


router = APIRouter(
    tags=[OAUTH2_AUTHORIZATION_CODE_FLOW_TAG], route_class=BrowserPageRoute
)


def _invalid_interaction(request: Request) -> HTMLResponse:
    """Render one safe error for missing, expired, or foreign interactions."""
    return render_page(
        request,
        "error.html",
        status_code=status.HTTP_400_BAD_REQUEST,
        title="Authorization unavailable",
        message="This authorization request is invalid or has expired.",
        link_url=None,
        link_label=None,
    )


@router.get(BUILTIN_AUTHORIZATION_CONSENT_PATH)
async def consent_page(  # noqa: PLR0913
    *,
    request: Request,
    interaction_service: AuthorizationInteractionServiceDep,
    lifecycle_service: BrowserSessionLifecycleServiceDep,
    user_ctx: PublicOptionalBrowserUserContextDep,
    settings: SettingsDep,
    transaction_id: Annotated[str, Query(min_length=1)],
) -> Response:
    """Continue a browser interaction, consuming it when consent is unnecessary."""
    if user_ctx is None:
        return no_store_redirect(
            authorization_interaction_entry_url(
                settings, transaction_id=transaction_id
            ),
            status_code=status.HTTP_303_SEE_OTHER,
        )
    result = await interaction_service.continue_interaction(
        transaction_id=transaction_id,
        user_ctx=user_ctx,
    )
    if result is None:
        return _invalid_interaction(request)
    if isinstance(result, AuthorizationRedirect):
        return authorization_response(result)
    csrf_token = await lifecycle_service.get_session_csrf(
        session_id=user_ctx.raw_session_id
    )
    return render_page(
        request,
        "auth/consent.html",
        client_name=result.client_name,
        scopes=result.requested_scope.split(),
        transaction_id=transaction_id,
        csrf_token=csrf_token,
    )
