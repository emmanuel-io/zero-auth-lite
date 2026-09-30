"""Built-in browser adapters for authentication-email workflows."""

from typing import Annotated
from urllib.parse import urlencode

from fastapi import APIRouter, Form, Query, Request, status
from starlette.responses import HTMLResponse, RedirectResponse

from app.browser_sessions.form_csrf import (
    get_or_create_pre_session_form_csrf,
    set_pre_session_form_csrf_cookie,
    validate_pre_session_form_csrf,
)
from app.core.errors.base import AppError
from app.db.dependencies import DbSessionDep
from app.openapi_tags import BUILTIN_AUTH_UI_TAG
from app.password.validation import validate_password_value
from app.settings.dependencies import CSRFSettingsDep, SettingsDep
from app.settings.ui import (
    BUILTIN_INVITATION_PATH,
    BUILTIN_PASSWORD_RESET_PATH,
    BUILTIN_VERIFICATION_PATH,
)
from app.web.auth.inputs import PasswordForm, WorkflowTokenForm, WorkflowTokenQuery
from app.web.redirects import workflow_completion_url
from app.web.rendering import no_store_redirect, render_page
from app.web.routes import BrowserPageRoute
from app.workflow_tokens.dependencies import WorkflowTokenConfirmationServiceDep


router = APIRouter(tags=[BUILTIN_AUTH_UI_TAG], route_class=BrowserPageRoute)


def _attach_page_csrf(
    response: HTMLResponse,
    *,
    csrf_token: str,
    csrf_settings: CSRFSettingsDep,
) -> HTMLResponse:
    """Attach anonymous CSRF state matching the rendered hidden value."""
    set_pre_session_form_csrf_cookie(response, csrf_token, csrf_settings)
    return response


def _render_password_page(  # noqa: PLR0913
    request: Request,
    *,
    csrf_settings: CSRFSettingsDep,
    token: str,
    title: str,
    action: str,
    submit_label: str,
    error: str | None = None,
    status_code: int = status.HTTP_200_OK,
) -> HTMLResponse:
    """Render a password workflow with fresh CSRF state."""
    csrf_token = get_or_create_pre_session_form_csrf(request, csrf_settings)
    response = render_page(
        request,
        "auth/password.html",
        status_code=status_code,
        csrf_token=csrf_token,
        token=token,
        title=title,
        action=action,
        submit_label=submit_label,
        error=error,
    )
    return _attach_page_csrf(
        response,
        csrf_token=csrf_token,
        csrf_settings=csrf_settings,
    )


def _invalid_token_page(request: Request) -> HTMLResponse:
    """Render a safe workflow-token failure."""
    return render_page(
        request,
        "error.html",
        status_code=status.HTTP_400_BAD_REQUEST,
        title="Link unavailable",
        message="This link is invalid, expired, or has already been used.",
        link_url=None,
        link_label=None,
    )


@router.get(BUILTIN_VERIFICATION_PATH)
async def verification_page(
    request: Request,
    csrf_settings: CSRFSettingsDep,
    token: WorkflowTokenQuery,
) -> HTMLResponse:
    """Render the confirmation page linked from verification email."""
    csrf_token = get_or_create_pre_session_form_csrf(request, csrf_settings)
    response = render_page(
        request,
        "auth/verify.html",
        csrf_token=csrf_token,
        token=token,
    )
    return _attach_page_csrf(
        response,
        csrf_token=csrf_token,
        csrf_settings=csrf_settings,
    )


@router.get("/auth-link-unavailable")
async def invalid_auth_link_page(request: Request) -> HTMLResponse:
    """Render the generic token failure after a PRG redirect."""
    return _invalid_token_page(request)


@router.post(BUILTIN_VERIFICATION_PATH)
async def submit_verification(  # noqa: PLR0913
    *,
    request: Request,
    service: WorkflowTokenConfirmationServiceDep,
    db_session: DbSessionDep,
    csrf_settings: CSRFSettingsDep,
    settings: SettingsDep,
    token: WorkflowTokenForm,
    csrf_token: Annotated[str | None, Form()] = None,
) -> RedirectResponse:
    """Consume a verification token through the canonical service."""
    validate_pre_session_form_csrf(
        request=request,
        csrf_token=csrf_token,
        csrf_settings=csrf_settings,
    )
    try:
        await service.confirm_verification(token)
    except AppError:
        await db_session.rollback()
        return no_store_redirect(
            "/auth-link-unavailable", status_code=status.HTTP_303_SEE_OTHER
        )
    return no_store_redirect(
        workflow_completion_url(settings, notice="email-verified"),
        status_code=status.HTTP_303_SEE_OTHER,
    )


@router.get(BUILTIN_PASSWORD_RESET_PATH)
async def reset_password_page(
    request: Request,
    csrf_settings: CSRFSettingsDep,
    token: WorkflowTokenQuery,
    error: Annotated[str | None, Query()] = None,
) -> HTMLResponse:
    """Render the password-reset page linked from email."""
    return _render_password_page(
        request,
        csrf_settings=csrf_settings,
        token=token,
        title="Reset password",
        action=BUILTIN_PASSWORD_RESET_PATH,
        submit_label="Reset password",
        error="Choose a password that meets all requirements." if error else None,
    )


@router.post(BUILTIN_PASSWORD_RESET_PATH)
async def submit_password_reset(  # noqa: PLR0913
    *,
    request: Request,
    service: WorkflowTokenConfirmationServiceDep,
    db_session: DbSessionDep,
    csrf_settings: CSRFSettingsDep,
    settings: SettingsDep,
    token: WorkflowTokenForm,
    password: PasswordForm,
    csrf_token: Annotated[str | None, Form()] = None,
) -> RedirectResponse:
    """Validate and apply a password reset through the canonical service."""
    validate_pre_session_form_csrf(
        request=request,
        csrf_token=csrf_token,
        csrf_settings=csrf_settings,
    )
    try:
        validated_password = validate_password_value(password)
    except ValueError:
        query = urlencode({"token": token, "error": "invalid"})
        return no_store_redirect(
            f"{BUILTIN_PASSWORD_RESET_PATH}?{query}",
            status_code=status.HTTP_303_SEE_OTHER,
        )
    try:
        await service.reset_password(token=token, password=validated_password)
    except AppError:
        await db_session.rollback()
        return no_store_redirect(
            "/auth-link-unavailable", status_code=status.HTTP_303_SEE_OTHER
        )
    return no_store_redirect(
        workflow_completion_url(settings, notice="password-reset"),
        status_code=status.HTTP_303_SEE_OTHER,
    )


@router.get(BUILTIN_INVITATION_PATH)
async def accept_invite_page(
    request: Request,
    csrf_settings: CSRFSettingsDep,
    token: WorkflowTokenQuery,
    error: Annotated[str | None, Query()] = None,
) -> HTMLResponse:
    """Render the invitation-acceptance page linked from email."""
    return _render_password_page(
        request,
        csrf_settings=csrf_settings,
        token=token,
        title="Accept invitation",
        action=BUILTIN_INVITATION_PATH,
        submit_label="Accept invitation",
        error="Choose a password that meets all requirements." if error else None,
    )


@router.post(BUILTIN_INVITATION_PATH)
async def submit_invite_acceptance(  # noqa: PLR0913
    *,
    request: Request,
    service: WorkflowTokenConfirmationServiceDep,
    db_session: DbSessionDep,
    csrf_settings: CSRFSettingsDep,
    settings: SettingsDep,
    token: WorkflowTokenForm,
    password: PasswordForm,
    csrf_token: Annotated[str | None, Form()] = None,
) -> RedirectResponse:
    """Validate and accept an invitation through the canonical service."""
    validate_pre_session_form_csrf(
        request=request,
        csrf_token=csrf_token,
        csrf_settings=csrf_settings,
    )
    try:
        validated_password = validate_password_value(password)
    except ValueError:
        query = urlencode({"token": token, "error": "invalid"})
        return no_store_redirect(
            f"{BUILTIN_INVITATION_PATH}?{query}",
            status_code=status.HTTP_303_SEE_OTHER,
        )
    try:
        await service.accept_invite(token=token, password=validated_password)
    except AppError:
        await db_session.rollback()
        return no_store_redirect(
            "/auth-link-unavailable", status_code=status.HTTP_303_SEE_OTHER
        )
    return no_store_redirect(
        workflow_completion_url(settings, notice="invite-accepted"),
        status_code=status.HTTP_303_SEE_OTHER,
    )
