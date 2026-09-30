"""Server-operator organization session browser routes."""

from typing import Annotated

from fastapi import APIRouter, Query, Request, Response

from app.browser_sessions.enums import BrowserSessionRevocationReason
from app.browser_sessions.response_transport import (
    request_session_cookie_clear_on_success,
)
from app.browser_sessions.service_dependencies import (
    BrowserSessionLifecycleServiceDep,
    BrowserSessionRevocationServiceDep,
)
from app.security.organization_security_session_dependencies import (
    OrganizationSecuritySessionAuthorizationServiceDep,
)
from app.security.session_revocation_dependencies import SecuritySessionRevocationDep
from app.web.management.dependencies import (
    OperatorFormDep,
    OperatorUIDep,
    OperatorUIOrganizationsServiceDep,
)
from app.web.management.forms import ConfirmedFormDep
from app.web.management.ids import OrganizationIdPath
from app.web.management.notices import ManagementNotice
from app.web.management.operator.views import OrganizationView
from app.web.management.responses import (
    authentication_navigation_url,
    mutation_success,
    render_management_page,
)
from app.web.routes import ManagementPageRoute


router = APIRouter(route_class=ManagementPageRoute)


@router.get("/organizations/{organization_id}/sessions")
async def organization_sessions(  # noqa: PLR0913, PLR0917
    organization_id: OrganizationIdPath,
    request: Request,
    service: OperatorUIOrganizationsServiceDep,
    lifecycle_service: BrowserSessionLifecycleServiceDep,
    user_ctx: OperatorUIDep,
    notice: Annotated[str | None, Query()] = None,
) -> Response:
    """Render the organization session list."""
    organization = await service.get(organization_id=organization_id)
    return await render_management_page(
        request,
        lifecycle_service,
        user_ctx,
        "management/operator/organization_sessions.html",
        organization=OrganizationView.from_dto(organization),
        notice=notice,
    )


@router.get("/organizations/{organization_id}/sessions/revoke")
async def confirm_revoke_organization_sessions(
    organization_id: OrganizationIdPath,
    request: Request,
    service: OperatorUIOrganizationsServiceDep,
    lifecycle_service: BrowserSessionLifecycleServiceDep,
    user_ctx: OperatorUIDep,
) -> Response:
    """Render the organization session-revocation confirmation."""
    organization = await service.get(organization_id=organization_id)
    return await render_management_page(
        request,
        lifecycle_service,
        user_ctx,
        "management/confirm.html",
        heading="Revoke organization sessions?",
        message=(
            f"This ends browser and OAuth2 sessions attributed to "
            f"{organization.name}. If this is your own organization, your "
            "session also ends."
        ),
        action=f"/management/operator/organizations/{organization_id}/sessions/revoke",
        cancel_url=f"/management/operator/organizations/{organization_id}/sessions",
        submit_label="Revoke organization sessions",
    )


@router.get("/organizations/{organization_id}/sessions/browser/delete")
async def confirm_delete_organization_browser_sessions(
    organization_id: OrganizationIdPath,
    request: Request,
    service: OperatorUIOrganizationsServiceDep,
    lifecycle_service: BrowserSessionLifecycleServiceDep,
    user_ctx: OperatorUIDep,
) -> Response:
    """Render the browser-session deletion confirmation."""
    organization = await service.get(organization_id=organization_id)
    return await render_management_page(
        request,
        lifecycle_service,
        user_ctx,
        "management/confirm.html",
        heading="Delete organization browser sessions?",
        message=(
            f"This permanently deletes browser sessions belonging to users in "
            f"{organization.name}. OAuth2 sessions are not affected."
        ),
        action=f"/management/operator/organizations/{organization_id}/sessions/browser/delete",
        cancel_url=f"/management/operator/organizations/{organization_id}/sessions",
        submit_label="Delete browser sessions",
    )


@router.post("/organizations/{organization_id}/sessions/browser/delete")
async def delete_organization_browser_sessions(
    organization_id: OrganizationIdPath,
    request: Request,
    authorization_service: OrganizationSecuritySessionAuthorizationServiceDep,
    revocation_service: BrowserSessionRevocationServiceDep,
    user_ctx: OperatorFormDep,
    _confirmation: ConfirmedFormDep,
) -> Response:
    """Delete every browser session for the organization."""
    authorization = await authorization_service.authorize(
        organization_public_id=organization_id,
        principal=user_ctx,
    )
    await revocation_service.delete_organization_sessions(
        organization_id=authorization.organization_id
    )
    actor_session_deleted = user_ctx.organization_id == authorization.organization_id
    if actor_session_deleted:
        request_session_cookie_clear_on_success(request)
    return mutation_success(
        request,
        authentication_navigation_url(request)
        if actor_session_deleted
        else f"/management/operator/organizations/{organization_id}/sessions",
        notice=ManagementNotice.BROWSER_SESSIONS_DELETED,
    )


@router.get("/organizations/{organization_id}/sessions/oauth2/delete")
async def confirm_delete_organization_oauth2_sessions(
    organization_id: OrganizationIdPath,
    request: Request,
    service: OperatorUIOrganizationsServiceDep,
    lifecycle_service: BrowserSessionLifecycleServiceDep,
    user_ctx: OperatorUIDep,
) -> Response:
    """Render the OAuth2-session deletion confirmation."""
    organization = await service.get(organization_id=organization_id)
    return await render_management_page(
        request,
        lifecycle_service,
        user_ctx,
        "management/confirm.html",
        heading="Delete organization OAuth2 sessions?",
        message=(
            f"This permanently deletes OAuth2 session families attributed to "
            f"{organization.name}. Browser sessions are not affected."
        ),
        action=f"/management/operator/organizations/{organization_id}/sessions/oauth2/delete",
        cancel_url=f"/management/operator/organizations/{organization_id}/sessions",
        submit_label="Delete OAuth2 sessions",
    )


@router.post("/organizations/{organization_id}/sessions/oauth2/delete")
async def delete_organization_oauth2_sessions(
    organization_id: OrganizationIdPath,
    request: Request,
    authorization_service: OrganizationSecuritySessionAuthorizationServiceDep,
    revocation_service: SecuritySessionRevocationDep,
    user_ctx: OperatorFormDep,
    _confirmation: ConfirmedFormDep,
) -> Response:
    """Delete every OAuth2 session for the organization."""
    authorization = await authorization_service.authorize(
        organization_public_id=organization_id,
        principal=user_ctx,
    )
    await revocation_service.clear_organization_oauth2_sessions(
        organization_id=authorization.organization_id
    )
    return mutation_success(
        request,
        f"/management/operator/organizations/{organization_id}/sessions",
        notice=ManagementNotice.OAUTH2_SESSIONS_DELETED,
    )


@router.post("/organizations/{organization_id}/sessions/revoke")
async def revoke_organization_sessions(
    organization_id: OrganizationIdPath,
    request: Request,
    authorization_service: OrganizationSecuritySessionAuthorizationServiceDep,
    revocation_service: SecuritySessionRevocationDep,
    user_ctx: OperatorFormDep,
    _confirmation: ConfirmedFormDep,
) -> Response:
    """Revoke every security session for the organization."""
    authorization = await authorization_service.authorize(
        organization_public_id=organization_id,
        principal=user_ctx,
    )
    await revocation_service.revoke_organization_security_sessions(
        organization_id=authorization.organization_id,
        browser_reason=BrowserSessionRevocationReason.ORGANIZATION_SESSIONS_REVOKED,
    )
    actor_session_revoked = user_ctx.organization_id == authorization.organization_id
    if actor_session_revoked:
        request_session_cookie_clear_on_success(request)
    return mutation_success(
        request,
        authentication_navigation_url(request)
        if actor_session_revoked
        else f"/management/operator/organizations/{organization_id}/sessions",
        notice=ManagementNotice.ORGANIZATION_SESSIONS_REVOKED,
    )
