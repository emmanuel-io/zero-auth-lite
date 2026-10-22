"""Current-organization OAuth2 session browser routes."""

from typing import Annotated

from fastapi import APIRouter, Query, Request, Response

from app.browser_sessions.service_dependencies import BrowserSessionLifecycleServiceDep
from app.oauth2.organization_oauth2_sessions.dependencies import (
    OrganizationOAuth2SessionServiceDep,
)
from app.web.management.dependencies import (
    OrganizationAdminFormDep,
    OrganizationAdminUIDep,
)
from app.web.management.forms import ConfirmedFormDep
from app.web.management.ids import (
    OAuth2ClientIdPath,
    OAuth2SessionIdPath,
)
from app.web.management.notices import ManagementNotice
from app.web.management.organization.queries import OrganizationOAuth2SessionFilters
from app.web.management.organization.views import OrganizationOAuth2SessionView
from app.web.management.pagination import page_url
from app.web.management.queries import ManagementPagination
from app.web.management.responses import mutation_success, render_management_page
from app.web.routes import ManagementPageRoute


router = APIRouter(route_class=ManagementPageRoute)


@router.get("/oauth2/sessions")
async def oauth2_sessions(  # noqa: PLR0913, PLR0917
    request: Request,
    service: OrganizationOAuth2SessionServiceDep,
    lifecycle_service: BrowserSessionLifecycleServiceDep,
    user_ctx: OrganizationAdminUIDep,
    query: Annotated[OrganizationOAuth2SessionFilters, Query()],
    pagination: Annotated[ManagementPagination, Query()],
    notice: Annotated[str | None, Query()] = None,
) -> Response:
    """Render the current organization OAuth2 session list."""
    page = await service.list_sessions(
        actor_ctx=user_ctx,
        client_id=query.client_id,
        grant_type=query.grant_type,
        user_public_id=query.user_id,
        active_only=query.active_only,
        offset=pagination.offset,
        limit=pagination.limit,
    )
    filters = {
        "client_id": query.client_id,
        "grant_type": query.grant_type,
        "user_id": query.user_id,
        "active_only": query.active_only,
    }
    return await render_management_page(
        request,
        lifecycle_service,
        user_ctx,
        "management/organization/oauth2_sessions.html",
        sessions=[OrganizationOAuth2SessionView.from_dto(item) for item in page.items],
        total=page.total,
        filters=filters,
        previous_url=(
            page_url(
                "/management/organization/oauth2/sessions",
                offset=pagination.offset - pagination.limit,
                limit=pagination.limit,
                **filters,
            )
            if pagination.offset > 0
            else None
        ),
        next_url=(
            page_url(
                "/management/organization/oauth2/sessions",
                offset=pagination.offset + pagination.limit,
                limit=pagination.limit,
                **filters,
            )
            if pagination.offset + pagination.limit < page.total
            else None
        ),
        notice=notice,
    )


@router.post("/oauth2/sessions/{session_id}/revoke")
async def revoke_oauth2_session(
    session_id: OAuth2SessionIdPath,
    request: Request,
    service: OrganizationOAuth2SessionServiceDep,
    user_ctx: OrganizationAdminFormDep,
    _confirmation: ConfirmedFormDep,
) -> Response:
    """Revoke the selected OAuth2 session."""
    await service.revoke_session(
        session_public_id=session_id,
        actor_ctx=user_ctx,
    )
    return mutation_success(
        request,
        "/management/organization/oauth2/sessions",
        notice=ManagementNotice.OAUTH2_SESSION_REVOKED,
    )


@router.post("/oauth2/clients/{client_id}/revoke")
async def revoke_client_sessions(
    client_id: OAuth2ClientIdPath,
    request: Request,
    service: OrganizationOAuth2SessionServiceDep,
    user_ctx: OrganizationAdminFormDep,
    _confirmation: ConfirmedFormDep,
) -> Response:
    """Revoke OAuth2 sessions issued to the selected client."""
    await service.revoke_client_token_families(client_id=client_id, actor_ctx=user_ctx)
    return mutation_success(
        request,
        "/management/organization/oauth2/sessions",
        notice=ManagementNotice.CLIENT_SESSIONS_REVOKED,
    )
