"""Built-in form adapters for authentication and session workflows."""

from logging import getLogger
from typing import Annotated

from fastapi import APIRouter, Form, Query, Request, Response, status
from pydantic import ValidationError
from starlette.responses import HTMLResponse, RedirectResponse

from app.browser_sessions.dependencies import (
    CurrentBrowserFormUserContextDep,
    get_resolved_browser_session,
    PublicOptionalBrowserUserContextDep,
    SessionRevocationServiceDep,
)
from app.browser_sessions.form_csrf import (
    get_or_create_pre_session_form_csrf,
    set_pre_session_form_csrf_cookie,
    validate_pre_session_form_csrf,
)
from app.browser_sessions.response_transport import (
    request_session_cookie_clear_on_success,
)
from app.core.errors.base import AppError
from app.db.dependencies import DbSessionDep
from app.events.dependencies import (
    AuthNotificationRequestServiceDep,
    EventPublisherDep,
)
from app.identity.dtos import RegistrationCreateDTO
from app.identity.public_ids import format_user_id
from app.identity.registration import RegistrationService
from app.identity.users.emails import validate_user_email
from app.openapi_tags import BUILTIN_AUTH_UI_TAG
from app.password.dependencies import PasswordHasherDep
from app.settings.dependencies import (
    CSRFSettingsDep,
    SettingsDep,
)
from app.settings.root import Settings
from app.web.redirects import authentication_entry_url, workflow_completion_url
from app.web.rendering import render_page


logger = getLogger(__name__)


def _redirect(path: str) -> RedirectResponse:
    """Return a no-store PRG redirect."""
    return RedirectResponse(
        path,
        status_code=status.HTTP_303_SEE_OTHER,
        headers={"Cache-Control": "no-store", "Pragma": "no-cache"},
    )


def _request_page(  # noqa: PLR0913
    request: Request,
    *,
    csrf_settings: CSRFSettingsDep,
    title: str,
    description: str,
    action: str,
    submit_label: str,
    email: str = "",
    error: str | None = None,
) -> HTMLResponse:
    """Render an anonymous email-request form with fresh CSRF state."""
    csrf_token = get_or_create_pre_session_form_csrf(request, csrf_settings)
    response = render_page(
        request,
        "auth/request.html",
        csrf_token=csrf_token,
        title=title,
        description=description,
        action=action,
        submit_label=submit_label,
        email=email,
        error=error,
    )
    set_pre_session_form_csrf_cookie(response, csrf_token, csrf_settings)
    return response


router = APIRouter(tags=[BUILTIN_AUTH_UI_TAG])
registration_router = APIRouter(tags=[BUILTIN_AUTH_UI_TAG])
session_router = APIRouter(tags=[BUILTIN_AUTH_UI_TAG])


@registration_router.get("/register")
async def registration_page(
    request: Request,
    csrf_settings: CSRFSettingsDep,
    error: Annotated[str | None, Query()] = None,
) -> HTMLResponse:
    """Render self-registration with anonymous CSRF state."""
    csrf_token = get_or_create_pre_session_form_csrf(request, csrf_settings)
    response = render_page(
        request,
        "auth/register.html",
        csrf_token=csrf_token,
        organization_name="",
        first_name="",
        last_name="",
        email="",
        error="Check the submitted registration details." if error else None,
    )
    set_pre_session_form_csrf_cookie(response, csrf_token, csrf_settings)
    return response


@registration_router.post("/register")
async def submit_registration(  # noqa: PLR0913
    *,
    request: Request,
    db_session: DbSessionDep,
    event_publisher: EventPublisherDep,
    password_hasher: PasswordHasherDep,
    csrf_settings: CSRFSettingsDep,
    settings: SettingsDep,
    email: Annotated[str, Form()],
    password: Annotated[str, Form()],
    organization_name: Annotated[str, Form()],
    first_name: Annotated[str, Form()] = "",
    last_name: Annotated[str, Form()] = "",
    csrf_token: Annotated[str | None, Form()] = None,
) -> RedirectResponse:
    """Validate a form and call the canonical registration service."""
    validate_pre_session_form_csrf(
        request=request, csrf_token=csrf_token, csrf_settings=csrf_settings
    )
    try:
        registration = RegistrationCreateDTO(
            email=email,
            password=password,
            organization_name=organization_name,
            first_name=first_name,
            last_name=last_name,
        )
        await RegistrationService(
            db_session=db_session,
            event_publisher=event_publisher,
            password_hasher=password_hasher,
        ).register(
            registration=registration,
        )
    except (ValidationError, AppError):
        await db_session.rollback()
        return _redirect("/register?error=invalid")
    return _redirect(workflow_completion_url(settings, notice="registered"))


@registration_router.get("/resend-verification")
async def resend_verification_page(
    request: Request, csrf_settings: CSRFSettingsDep
) -> HTMLResponse:
    """Render the verification-notification request form."""
    return _request_page(
        request,
        csrf_settings=csrf_settings,
        title="Resend verification email",
        description="Request a new verification link.",
        action="/resend-verification",
        submit_label="Send verification email",
    )


@registration_router.post("/resend-verification")
async def submit_resend_verification(  # noqa: PLR0913
    *,
    request: Request,
    notification_requests: AuthNotificationRequestServiceDep,
    csrf_settings: CSRFSettingsDep,
    settings: SettingsDep,
    email: Annotated[str, Form()],
    csrf_token: Annotated[str | None, Form()] = None,
) -> RedirectResponse:
    """Publish the same opaque verification request used by the JSON adapter."""
    validate_pre_session_form_csrf(
        request=request, csrf_token=csrf_token, csrf_settings=csrf_settings
    )
    try:
        validated_email = validate_user_email(email)
    except ValidationError:
        return _redirect("/resend-verification")
    await notification_requests.request_account_verification(validated_email)
    return _redirect(workflow_completion_url(settings, notice="verification-sent"))


@router.get("/forgot-password")
async def forgot_password_page(
    request: Request, csrf_settings: CSRFSettingsDep
) -> HTMLResponse:
    """Render the opaque password-reset request form."""
    return _request_page(
        request,
        csrf_settings=csrf_settings,
        title="Forgot password",
        description="Request a password-reset link.",
        action="/forgot-password",
        submit_label="Send reset email",
    )


@router.post("/forgot-password")
async def submit_forgot_password(  # noqa: PLR0913
    *,
    request: Request,
    notification_requests: AuthNotificationRequestServiceDep,
    csrf_settings: CSRFSettingsDep,
    settings: SettingsDep,
    email: Annotated[str, Form()],
    csrf_token: Annotated[str | None, Form()] = None,
) -> RedirectResponse:
    """Publish the same opaque reset request used by the JSON adapter."""
    validate_pre_session_form_csrf(
        request=request, csrf_token=csrf_token, csrf_settings=csrf_settings
    )
    try:
        validated_email = validate_user_email(email)
    except ValidationError:
        return _redirect("/forgot-password")
    await notification_requests.request_password_reset(validated_email)
    return _redirect(workflow_completion_url(settings, notice="reset-sent"))


@session_router.get("/logout")
async def logout_page(
    request: Request,
    principal: PublicOptionalBrowserUserContextDep,
    settings: SettingsDep,
) -> Response:
    """Render logout using the authenticated session CSRF value."""
    if principal is None:
        return _redirect(authentication_entry_url(settings))
    session = get_resolved_browser_session(request)
    if session is None:
        msg = "Resolved browser context requires matching session state."
        raise RuntimeError(msg)
    return render_page(request, "auth/logout.html", csrf_token=session.csrf)


@session_router.post("/logout")
async def submit_logout(
    request: Request,
    principal: CurrentBrowserFormUserContextDep,
    revocation_service: SessionRevocationServiceDep,
    settings: SettingsDep,
) -> RedirectResponse:
    """Revoke the current session through the canonical revocation service."""
    revoked = await revocation_service.logout(session_id=principal.session_id)
    logger.info(
        (
            "event=browser_session_revocation outcome=attempted subject_id=%s "
            "reason=logout revoked_sessions=%s"
        ),
        format_user_id(principal.user_public_id)
        if principal.user_public_id
        else "unknown",
        int(revoked),
    )
    request_session_cookie_clear_on_success(request)
    return _redirect(workflow_completion_url(settings, notice="signed-out"))


def create_auth_workflow_router(settings: Settings) -> APIRouter:
    """Compose built-in form workflows according to feature flags."""
    composed = APIRouter()
    composed.include_router(router)
    if settings.session.enabled:
        composed.include_router(session_router)
    if settings.auth.registration_enabled:
        composed.include_router(registration_router)
    return composed
