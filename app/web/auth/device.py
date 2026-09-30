"""Built-in browser interaction for the OAuth2 device grant."""

from typing import Annotated
from urllib.parse import urlencode, urlsplit, urlunsplit

from fastapi import APIRouter, Depends, Query, Request, Response, status
from starlette.responses import HTMLResponse

from app.browser_sessions.dependencies import (
    CurrentBrowserFormUserContextDep,
    PublicOptionalBrowserUserContextDep,
)
from app.browser_sessions.service_dependencies import BrowserSessionLifecycleServiceDep
from app.oauth2.devices.dependencies import DeviceAuthorizationServiceDep
from app.oauth2.devices.forms import DeviceVerificationForm
from app.oauth2.specs import OAuth2Specs
from app.openapi_tags import OAUTH2_DEVICE_FLOW_TAG
from app.settings.dependencies import SettingsDep
from app.settings.ui import BUILTIN_DEVICE_INTERACTION_PATH
from app.web.rendering import no_store_redirect, render_page
from app.web.routes import BrowserPageRoute


router = APIRouter(tags=[OAUTH2_DEVICE_FLOW_TAG], route_class=BrowserPageRoute)


@router.get(BUILTIN_DEVICE_INTERACTION_PATH, name="device_verify_page")
async def device_verify_page(
    request: Request,
    lifecycle_service: BrowserSessionLifecycleServiceDep,
    user_ctx: PublicOptionalBrowserUserContextDep,
    settings: SettingsDep,
    user_code: Annotated[
        str | None, Query(max_length=OAuth2Specs.PROTOCOL_VALUE_LENGTH_MAX)
    ] = None,
) -> Response:
    """Authenticate the user when needed, then render device verification."""
    if user_ctx is None:
        query = urlencode({"user_code": user_code}) if user_code is not None else ""
        login_url = urlsplit(settings.ui.urls.authorization_interaction)
        return no_store_redirect(
            urlunsplit(
                (
                    login_url.scheme,
                    login_url.netloc,
                    login_url.path,
                    query,
                    "",
                )
            ),
            status_code=status.HTTP_303_SEE_OTHER,
        )
    csrf_token = await lifecycle_service.get_session_csrf(
        session_id=user_ctx.raw_session_id
    )
    return render_page(
        request,
        "auth/device.html",
        user_code=user_code or "",
        csrf_token=csrf_token,
        error=None,
    )


@router.post(BUILTIN_DEVICE_INTERACTION_PATH)
async def device_verify_submit(
    request: Request,
    device_authorization_service: DeviceAuthorizationServiceDep,
    user_ctx: CurrentBrowserFormUserContextDep,
    settings: SettingsDep,
    form: Annotated[DeviceVerificationForm, Depends()],
) -> HTMLResponse:
    """Apply an authenticated device authorization decision."""
    ok = await device_authorization_service.decide_device_authorization(
        user_ctx=user_ctx,
        user_code=form.user_code,
        approve=form.decision == "approve",
    )
    if not ok:
        return render_page(
            request,
            "error.html",
            status_code=status.HTTP_400_BAD_REQUEST,
            title="Invalid or expired code",
            message="This device request is invalid, expired, or already completed.",
            link_url=settings.ui.urls.device_interaction,
            link_label="Try another code",
        )
    approved = form.decision == "approve"
    return render_page(
        request,
        "auth/result.html",
        title="Approved" if approved else "Denied",
        message=(
            "You can return to your device."
            if approved
            else "The device was not granted access."
        ),
        link_url=None,
        link_label=None,
    )
