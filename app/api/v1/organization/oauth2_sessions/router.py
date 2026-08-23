"""Current-organization OAuth2 session administration routes."""

from typing import Annotated

from fastapi import APIRouter, Path, Query, Response, Security, status

from app.api.error_responses import app_error_responses
from app.api.schemas import DEFAULT_PAGE_LIMIT_MAX, PaginatedResponse
from app.api.v1.organization.oauth2_sessions.schemas import (
    OAuth2RevocationResponse,
    OAuth2SessionResponse,
)
from app.browser_sessions.errors import (
    CSRFCookieHeaderMismatchError,
    CSRFHeaderSessionMismatchError,
    CSRFMissingCookieError,
    CSRFMissingHeaderError,
    SessionInvalidError,
)
from app.errors import ForbiddenOperationError, UnauthorizedError
from app.identity.public_ids import parse_user_id, USER_ID_PATTERN
from app.oauth2.organization_oauth2_session_dependencies import (
    OrganizationOAuth2SessionServiceDep,
)
from app.oauth2.organization_oauth2_sessions import (
    OrganizationOAuth2SessionNotFoundError,
)
from app.oauth2.public_ids import OAUTH2_SESSION_ID_PATTERN, parse_oauth2_session_id
from app.oauth2.settings import OAuth2GrantType
from app.oauth2.specs import OAuth2Specs
from app.openapi_tags import ORGANIZATION_ADMINISTRATION_V1_TAG
from app.security.authorization import require_organization_admin_permission
from app.security.dtos import UserPrincipalContext
from app.security.permissions import Permission


router = APIRouter(prefix="/oauth2", tags=[ORGANIZATION_ADMINISTRATION_V1_TAG])
OrganizationOAuth2SessionListResponse = PaginatedResponse[OAuth2SessionResponse]
OAUTH2_SESSION_READ_AUTH_RESPONSES = app_error_responses(
    UnauthorizedError,
    SessionInvalidError,
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
    SessionInvalidError,
    ForbiddenOperationError,
    CSRFMissingCookieError,
    CSRFMissingHeaderError,
    CSRFCookieHeaderMismatchError,
    CSRFHeaderSessionMismatchError,
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
    SessionInvalidError,
    ForbiddenOperationError,
    CSRFMissingCookieError,
    CSRFMissingHeaderError,
    CSRFCookieHeaderMismatchError,
    CSRFHeaderSessionMismatchError,
    OrganizationOAuth2SessionNotFoundError,
    descriptions={
        status.HTTP_401_UNAUTHORIZED: "Missing or invalid authentication.",
        status.HTTP_403_FORBIDDEN: (
            "Organization-admin role, the organization:write permission, and valid "
            "CSRF proof are required."
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
async def list_oauth2_sessions(  # noqa: PLR0913
    *,
    response: Response,
    service: OrganizationOAuth2SessionServiceDep,
    admin_ctx: OrganizationOAuth2SessionsReadDep,
    client_id: Annotated[
        str | None,
        Query(
            min_length=1,
            max_length=OAuth2Specs.CLIENT_ID_LENGTH_MAX,
            description="Return sessions issued to this OAuth2 client.",
        ),
    ] = None,
    grant_type: Annotated[
        OAuth2GrantType | None,
        Query(description="Return sessions created by this OAuth2 grant type."),
    ] = None,
    user_id: Annotated[
        str | None,
        Query(
            pattern=USER_ID_PATTERN,
            description="Return sessions belonging to this organization user.",
        ),
    ] = None,
    active_only: Annotated[
        bool,
        Query(
            description=(
                "Exclude expired families when true. Revoked families are deleted "
                "and are never returned."
            )
        ),
    ] = True,
    offset: Annotated[
        int,
        Query(ge=0, description="Number of matching sessions to skip."),
    ] = 0,
    limit: Annotated[
        int,
        Query(
            ge=1,
            le=DEFAULT_PAGE_LIMIT_MAX,
            description="Maximum number of sessions to return.",
        ),
    ] = 100,
) -> OrganizationOAuth2SessionListResponse:
    """List retained current token families in the current organization."""
    response.headers["Cache-Control"] = "no-store"
    page = await service.list_sessions(
        admin_ctx=admin_ctx,
        client_id=client_id,
        grant_type=grant_type,
        user_public_id=parse_user_id(user_id) if user_id is not None else None,
        active_only=active_only,
        offset=offset,
        limit=limit,
    )
    return OrganizationOAuth2SessionListResponse(
        items=[
            OAuth2SessionResponse.model_validate(session, from_attributes=True)
            for session in page.items
        ],
        offset=offset,
        limit=limit,
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
        str,
        Path(min_length=1, max_length=OAuth2Specs.CLIENT_ID_LENGTH_MAX),
    ],
    service: OrganizationOAuth2SessionServiceDep,
    admin_ctx: OrganizationOAuth2SessionsWriteDep,
) -> OAuth2RevocationResponse:
    """Revoke every token family issued to one client in the current organization."""
    dto = await service.revoke_client_token_families(
        client_id=client_id,
        admin_ctx=admin_ctx,
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
        str,
        Path(
            pattern=OAUTH2_SESSION_ID_PATTERN,
            description="OAuth2 session identifier",
        ),
    ],
    service: OrganizationOAuth2SessionServiceDep,
    admin_ctx: OrganizationOAuth2SessionsWriteDep,
) -> OAuth2RevocationResponse:
    """Revoke one token family and end its OAuth2 session."""
    dto = await service.revoke_session(
        session_public_id=parse_oauth2_session_id(session_id),
        admin_ctx=admin_ctx,
    )
    return OAuth2RevocationResponse.model_validate(dto, from_attributes=True)
