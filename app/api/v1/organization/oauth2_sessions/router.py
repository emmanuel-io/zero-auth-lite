"""Current-organization OAuth2 session administration routes."""

from typing import Annotated

from fastapi import APIRouter, Path, Security, status
from pydantic import UUID4

from app.api.error_responses import app_error_responses
from app.api.schemas import PaginatedResponse
from app.api.v1.organization.oauth2_sessions.mapping import (
    organization_oauth2_session_response,
)
from app.api.v1.organization.oauth2_sessions.schemas import (
    OAuth2RevocationResponse,
    OrganizationOAuth2SessionListQueryDep,
    OrganizationOAuth2SessionResponse,
)
from app.browser_sessions.errors import (
    BrowserSessionInvalidError,
    CSRF_ERRORS,
)
from app.core.errors.common import ForbiddenOperationError, UnauthorizedError
from app.oauth2.organization_oauth2_sessions.dependencies import (
    OrganizationOAuth2SessionServiceDep,
)
from app.oauth2.organization_oauth2_sessions.service import (
    OrganizationOAuth2SessionNotFoundError,
)
from app.openapi_tags import ORGANIZATION_ADMINISTRATION_V1_TAG
from app.security.authorization import require_organization_admin_permission
from app.security.permissions import Permission
from app.security.principals import UserPrincipalContext


router = APIRouter(prefix="/oauth2", tags=[ORGANIZATION_ADMINISTRATION_V1_TAG])
OrganizationOAuth2SessionListResponse = PaginatedResponse[
    OrganizationOAuth2SessionResponse
]
OAUTH2_SESSION_READ_AUTH_RESPONSES = app_error_responses(
    UnauthorizedError,
    BrowserSessionInvalidError,
    ForbiddenOperationError,
    descriptions={
        status.HTTP_401_UNAUTHORIZED: "Missing or invalid authentication.",
        status.HTTP_403_FORBIDDEN: (
            "Organization-admin role and the organization:read permission are both "
            "required. An OAuth2 scope or server-operator role alone does not "
            "grant organization-admin access."
        ),
    },
)
OAUTH2_SESSION_WRITE_AUTH_RESPONSES = app_error_responses(
    UnauthorizedError,
    BrowserSessionInvalidError,
    ForbiddenOperationError,
    *CSRF_ERRORS,
    descriptions={
        status.HTTP_401_UNAUTHORIZED: "Missing or invalid authentication.",
        status.HTTP_403_FORBIDDEN: (
            "Organization-admin role and the organization:write permission are both "
            "required. An OAuth2 scope or server-operator role alone does not "
            "grant organization-admin access; browser sessions must also pass CSRF "
            "validation."
        ),
    },
)
OAUTH2_SESSION_REVOCATION_RESPONSES = app_error_responses(
    UnauthorizedError,
    BrowserSessionInvalidError,
    ForbiddenOperationError,
    *CSRF_ERRORS,
    OrganizationOAuth2SessionNotFoundError,
    descriptions={
        status.HTTP_401_UNAUTHORIZED: "Missing or invalid authentication.",
        status.HTTP_403_FORBIDDEN: (
            "The organization-admin role or organization:write permission is "
            "missing, or a browser-session request lacks valid CSRF proof."
        ),
        status.HTTP_404_NOT_FOUND: (
            "OAuth2 session not found in the authenticated organization."
        ),
    },
)
OrganizationOAuth2SessionsReadDep = Annotated[
    UserPrincipalContext,
    Security(
        require_organization_admin_permission(Permission.ORGANIZATION_READ),
        scopes=[Permission.ORGANIZATION_READ.value],
    ),
]
OrganizationOAuth2SessionsWriteDep = Annotated[
    UserPrincipalContext,
    Security(
        require_organization_admin_permission(Permission.ORGANIZATION_WRITE),
        scopes=[Permission.ORGANIZATION_WRITE.value],
    ),
]


@router.get(
    "/sessions",
    status_code=status.HTTP_200_OK,
    summary="List retained organization OAuth2 token families",
    responses={
        200: {
            "description": "Retained OAuth2 token families retrieved successfully.",
            "headers": {
                "Cache-Control": {
                    "description": "Prevents storage of sensitive session data.",
                    "schema": {"type": "string", "const": "no-store"},
                }
            },
        },
        **OAUTH2_SESSION_READ_AUTH_RESPONSES,
    },
)
async def list_oauth2_sessions(
    *,
    service: OrganizationOAuth2SessionServiceDep,
    admin_ctx: OrganizationOAuth2SessionsReadDep,
    query: OrganizationOAuth2SessionListQueryDep,
) -> OrganizationOAuth2SessionListResponse:
    """List retained current token families in the current organization."""
    page = await service.list_sessions(
        actor_ctx=admin_ctx,
        client_id=query.client_id,
        grant_type=query.grant_type,
        user_public_id=(query.user_id if query.user_id is not None else None),
        active_only=query.active_only,
        offset=query.offset,
        limit=query.limit,
    )
    return OrganizationOAuth2SessionListResponse(
        items=[organization_oauth2_session_response(session) for session in page.items],
        offset=query.offset,
        limit=query.limit,
        total=page.total,
    )


@router.delete(
    "/clients/{client_id}/tokens",
    status_code=status.HTTP_200_OK,
    summary="Revoke a client's tokens in the current organization",
    responses=OAUTH2_SESSION_WRITE_AUTH_RESPONSES,
)
async def revoke_oauth2_client_token_families(
    client_id: Annotated[
        UUID4,
        Path(description="OAuth2 client identifier"),
    ],
    service: OrganizationOAuth2SessionServiceDep,
    admin_ctx: OrganizationOAuth2SessionsWriteDep,
) -> OAuth2RevocationResponse:
    """Revoke every token family issued to one client in the current organization."""
    dto = await service.revoke_client_token_families(
        client_id=client_id,
        actor_ctx=admin_ctx,
    )
    return OAuth2RevocationResponse.model_validate(dto, from_attributes=True)


@router.delete(
    "/sessions/{session_id}",
    status_code=status.HTTP_200_OK,
    summary="Revoke one OAuth2 session in the current organization",
    responses=OAUTH2_SESSION_REVOCATION_RESPONSES,
)
async def revoke_oauth2_session(
    session_id: Annotated[
        UUID4,
        Path(
            description="OAuth2 session identifier",
        ),
    ],
    service: OrganizationOAuth2SessionServiceDep,
    admin_ctx: OrganizationOAuth2SessionsWriteDep,
) -> OAuth2RevocationResponse:
    """Revoke one token family and end its OAuth2 session."""
    dto = await service.revoke_session(
        session_public_id=session_id,
        actor_ctx=admin_ctx,
    )
    return OAuth2RevocationResponse.model_validate(dto, from_attributes=True)
