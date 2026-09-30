"""Organization-admin user security-session browser routes."""

from fastapi import APIRouter, Request, Response

from app.browser_sessions.enums import BrowserSessionRevocationReason
from app.browser_sessions.service_dependencies import (
    BrowserSessionLifecycleServiceDep,
    BrowserSessionRevocationServiceDep,
)
from app.security.session_revocation_dependencies import SecuritySessionRevocationDep
from app.web.management.dependencies import (
    OrganizationAdminFormDep,
    OrganizationAdminUIDep,
    OrganizationFormUsersServiceDep,
    OrganizationUIUsersServiceDep,
)
from app.web.management.forms import ConfirmedFormDep
from app.web.management.ids import UserIdPath
from app.web.management.user_session_actions import (
    delete_user_browser_sessions,
    delete_user_oauth2_sessions,
    render_user_session_confirmation,
    revoke_user_sessions,
    UserSessionOperation,
)
from app.web.routes import ManagementPageRoute


USER_PATH_PREFIX = "/management/organization/users"
router = APIRouter(route_class=ManagementPageRoute)


def _organization_user_path(user_id: UserIdPath) -> str:
    """Return the management path for one organization-visible user."""
    return f"{USER_PATH_PREFIX}/{user_id}"


@router.get("/users/{user_id}/sessions/browser/delete")
async def confirm_organization_user_browser_session_deletion(
    user_id: UserIdPath,
    request: Request,
    users_service: OrganizationUIUsersServiceDep,
    lifecycle_service: BrowserSessionLifecycleServiceDep,
    user_ctx: OrganizationAdminUIDep,
) -> Response:
    """Confirm deletion of one organization-visible user's browser sessions."""
    return await render_user_session_confirmation(
        request=request,
        lifecycle_service=lifecycle_service,
        user_ctx=user_ctx,
        users_service=users_service,
        target_public_id=user_id,
        user_path=_organization_user_path(user_id),
        operation=UserSessionOperation.DELETE_BROWSER,
    )


@router.get("/users/{user_id}/sessions/oauth2/delete")
async def confirm_organization_user_oauth2_session_deletion(
    user_id: UserIdPath,
    request: Request,
    users_service: OrganizationUIUsersServiceDep,
    lifecycle_service: BrowserSessionLifecycleServiceDep,
    user_ctx: OrganizationAdminUIDep,
) -> Response:
    """Confirm deletion of one organization-visible user's OAuth2 sessions."""
    return await render_user_session_confirmation(
        request=request,
        lifecycle_service=lifecycle_service,
        user_ctx=user_ctx,
        users_service=users_service,
        target_public_id=user_id,
        user_path=_organization_user_path(user_id),
        operation=UserSessionOperation.DELETE_OAUTH2,
    )


@router.get("/users/{user_id}/sessions/revoke")
async def confirm_organization_user_session_revocation(
    user_id: UserIdPath,
    request: Request,
    users_service: OrganizationUIUsersServiceDep,
    lifecycle_service: BrowserSessionLifecycleServiceDep,
    user_ctx: OrganizationAdminUIDep,
) -> Response:
    """Confirm revocation of all sessions for one organization-visible user."""
    return await render_user_session_confirmation(
        request=request,
        lifecycle_service=lifecycle_service,
        user_ctx=user_ctx,
        users_service=users_service,
        target_public_id=user_id,
        user_path=_organization_user_path(user_id),
        operation=UserSessionOperation.REVOKE_ALL,
    )


@router.post("/users/{user_id}/sessions/browser/delete")
async def delete_organization_user_browser_sessions(
    user_id: UserIdPath,
    request: Request,
    users_service: OrganizationFormUsersServiceDep,
    revocation_service: BrowserSessionRevocationServiceDep,
    user_ctx: OrganizationAdminFormDep,
    _confirmation: ConfirmedFormDep,
) -> Response:
    """Delete one organization-visible user's browser sessions."""
    return await delete_user_browser_sessions(
        request=request,
        users_service=users_service,
        revocation_service=revocation_service,
        target_public_id=user_id,
        current_user_id=user_ctx.user_id,
        user_path=_organization_user_path(user_id),
    )


@router.post("/users/{user_id}/sessions/oauth2/delete")
async def delete_organization_user_oauth2_sessions(
    user_id: UserIdPath,
    request: Request,
    users_service: OrganizationFormUsersServiceDep,
    revocation_service: SecuritySessionRevocationDep,
    _user_ctx: OrganizationAdminFormDep,
    _confirmation: ConfirmedFormDep,
) -> Response:
    """Delete one organization-visible user's OAuth2 sessions."""
    return await delete_user_oauth2_sessions(
        request=request,
        users_service=users_service,
        revocation_service=revocation_service,
        target_public_id=user_id,
        user_path=_organization_user_path(user_id),
    )


@router.post("/users/{user_id}/sessions/revoke")
async def revoke_organization_user_sessions(
    user_id: UserIdPath,
    request: Request,
    users_service: OrganizationFormUsersServiceDep,
    revocation_service: SecuritySessionRevocationDep,
    user_ctx: OrganizationAdminFormDep,
    _confirmation: ConfirmedFormDep,
) -> Response:
    """Revoke all sessions belonging to one organization-visible user."""
    return await revoke_user_sessions(
        request=request,
        users_service=users_service,
        revocation_service=revocation_service,
        target_public_id=user_id,
        current_user_id=user_ctx.user_id,
        user_path=_organization_user_path(user_id),
        browser_reason=(
            BrowserSessionRevocationReason.ORGANIZATION_ADMIN_REVOKED_USER_SESSIONS
        ),
    )
