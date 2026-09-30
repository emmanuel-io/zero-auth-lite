"""Current-organization security-session browser routes."""

from fastapi import APIRouter, Request, Response

from app.browser_sessions.enums import BrowserSessionRevocationReason
from app.browser_sessions.response_transport import (
    request_session_cookie_clear_on_success,
)
from app.browser_sessions.service_dependencies import (
    BrowserSessionLifecycleServiceDep,
    BrowserSessionRevocationServiceDep,
)
from app.security.session_revocation_dependencies import SecuritySessionRevocationDep
from app.web.management.dependencies import (
    OrganizationAdminFormDep,
    OrganizationAdminUIDep,
)
from app.web.management.forms import ConfirmedFormDep
from app.web.management.notices import ManagementNotice
from app.web.management.responses import (
    authentication_navigation_url,
    mutation_success,
    render_management_page,
)
from app.web.routes import ManagementPageRoute


router = APIRouter(route_class=ManagementPageRoute)


@router.get("/sessions/browser/delete")
async def confirm_delete_browser_sessions(
    request: Request,
    lifecycle_service: BrowserSessionLifecycleServiceDep,
    user_ctx: OrganizationAdminUIDep,
) -> Response:
    """Render the browser-session deletion confirmation."""
    return await render_management_page(
        request,
        lifecycle_service,
        user_ctx,
        "management/confirm.html",
        heading="Delete organization browser sessions?",
        message=(
            "This permanently deletes browser sessions belonging to users in "
            f"{user_ctx.organization_name}. OAuth2 sessions are not affected. "
            "Your current browser session also ends."
        ),
        action="/management/organization/sessions/browser/delete",
        cancel_url="/management/organization",
        submit_label="Delete browser sessions",
    )


@router.post("/sessions/browser/delete")
async def delete_browser_sessions(
    request: Request,
    service: BrowserSessionRevocationServiceDep,
    user_ctx: OrganizationAdminFormDep,
    _confirmation: ConfirmedFormDep,
) -> Response:
    """Delete browser sessions in the current organization."""
    await service.delete_organization_sessions(organization_id=user_ctx.organization_id)
    request_session_cookie_clear_on_success(request)
    return mutation_success(
        request,
        authentication_navigation_url(request),
        notice=ManagementNotice.BROWSER_SESSIONS_DELETED,
    )


@router.get("/sessions/oauth2/delete")
async def confirm_delete_oauth2_sessions(
    request: Request,
    lifecycle_service: BrowserSessionLifecycleServiceDep,
    user_ctx: OrganizationAdminUIDep,
) -> Response:
    """Render the OAuth2-session deletion confirmation."""
    return await render_management_page(
        request,
        lifecycle_service,
        user_ctx,
        "management/confirm.html",
        heading="Delete organization OAuth2 sessions?",
        message=(
            "This permanently deletes OAuth2 session families attributed to "
            f"{user_ctx.organization_name}. Browser sessions are not affected."
        ),
        action="/management/organization/sessions/oauth2/delete",
        cancel_url="/management/organization",
        submit_label="Delete OAuth2 sessions",
    )


@router.post("/sessions/oauth2/delete")
async def delete_oauth2_sessions(
    request: Request,
    service: SecuritySessionRevocationDep,
    user_ctx: OrganizationAdminFormDep,
    _confirmation: ConfirmedFormDep,
) -> Response:
    """Delete OAuth2 sessions in the current organization."""
    await service.clear_organization_oauth2_sessions(
        organization_id=user_ctx.organization_id
    )
    return mutation_success(
        request,
        "/management/organization",
        notice=ManagementNotice.OAUTH2_SESSIONS_DELETED,
    )


@router.get("/sessions/revoke")
async def confirm_revoke_all_sessions(
    request: Request,
    lifecycle_service: BrowserSessionLifecycleServiceDep,
    user_ctx: OrganizationAdminUIDep,
) -> Response:
    """Render the global session-revocation confirmation."""
    return await render_management_page(
        request,
        lifecycle_service,
        user_ctx,
        "management/confirm.html",
        heading="Revoke all organization sessions?",
        message=(
            "This ends browser and OAuth2 sessions attributed to "
            f"{user_ctx.organization_name}. Your current browser session also "
            "ends."
        ),
        action="/management/organization/sessions/revoke",
        cancel_url="/management/organization",
        submit_label="Revoke all sessions",
    )


@router.post("/sessions/revoke")
async def revoke_all_sessions(
    request: Request,
    service: SecuritySessionRevocationDep,
    user_ctx: OrganizationAdminFormDep,
    _confirmation: ConfirmedFormDep,
) -> Response:
    """Revoke every browser and OAuth2 session."""
    await service.revoke_organization_security_sessions(
        organization_id=user_ctx.organization_id,
        browser_reason=BrowserSessionRevocationReason.ORGANIZATION_SESSIONS_REVOKED,
    )
    request_session_cookie_clear_on_success(request)
    return mutation_success(
        request,
        authentication_navigation_url(request),
        notice=ManagementNotice.ORGANIZATION_SESSIONS_REVOKED,
    )
