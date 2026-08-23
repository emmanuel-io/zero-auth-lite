"""Built-in browser interaction for the OAuth2 device grant."""

from typing import Annotated

from fastapi import APIRouter, Depends, Query, Request, Response, status
from starlette.responses import HTMLResponse, RedirectResponse

from app.browser_sessions.dependencies import (
    CurrentBrowserFormUserContextDep,
    PublicOptionalBrowserUserContextDep,
    SessionLifecycleServiceDep,
)
from app.oauth2.devices.dependencies import DeviceAuthorizationServiceDep
from app.oauth2.devices.forms import DeviceVerificationForm
from app.openapi_tags import OAUTH2_DEVICE_FLOW_TAG
from app.settings.dependencies import SettingsDep
from app.web.redirects import authentication_entry_url
from app.web.rendering import render_page


router = APIRouter(tags=[OAUTH2_DEVICE_FLOW_TAG])


@router.get("/oauth2/device/verify", name="device_verify_page")
async def device_verify_page(
    request: Request,
    lifecycle_service: SessionLifecycleServiceDep,
    user_ctx: PublicOptionalBrowserUserContextDep,
    settings: SettingsDep,
    user_code: Annotated[str | None, Query()] = None,
) -> Response:
    """Authenticate the user when needed, then render device verification."""
    if user_ctx is None:
        return RedirectResponse(
            authentication_entry_url(settings, device_code=user_code),
            status_code=status.HTTP_303_SEE_OTHER,
        )
    csrf_token = await lifecycle_service.get_session_csrf(
        session_id=user_ctx.session_id
    )
    return render_page(
        request,
        "auth/device.html",
        user_code=user_code or "",
        csrf_token=csrf_token,
        error=None,
    )


@router.post("/oauth2/device/verify")
async def device_verify_submit(
    request: Request,
    device_authorization_service: DeviceAuthorizationServiceDep,
    user_ctx: CurrentBrowserFormUserContextDep,
    form: Annotated[DeviceVerificationForm, Depends()],
) -> HTMLResponse:
    """Apply an authenticated device authorization decision."""
    ok = await device_authorization_service.approve_device_authorization(
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
            link_url="/oauth2/device/verify",
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
