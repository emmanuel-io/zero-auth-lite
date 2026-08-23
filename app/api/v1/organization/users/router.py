"""Current-organization user administration API routes."""

from datetime import date
from typing import Annotated

from fastapi import APIRouter, Query, Response, Security, status

from app.api.dependencies.date_ranges import validate_date_range
from app.api.dependencies.ids import parse_user_id, UserIdPath
from app.api.error_responses import app_error_responses
from app.api.errors import StartDateAfterEndDateError
from app.api.schemas import DEFAULT_PAGE_LIMIT_MAX, PaginatedResponse
from app.api.v1.organization.users.schemas import (
    OrganizationUserCreateRequest,
    OrganizationUserPatchRequest,
    OrganizationUserReplaceRequest,
    OrganizationUserResponse,
)
from app.browser_sessions.errors import (
    CSRFCookieHeaderMismatchError,
    CSRFHeaderSessionMismatchError,
    CSRFMissingCookieError,
    CSRFMissingHeaderError,
    SessionInvalidError,
)
from app.db.errors import (
    CheckViolationError,
    ForeignKeyViolationError,
    NotNullViolationError,
    UniqueViolationError,
)
from app.errors import (
    ForbiddenOperationError,
    ObjectAlreadyExistsError,
    ObjectNotFoundError,
    UnauthorizedError,
)
from app.identity.dependencies import OrganizationUsersServiceDep
from app.identity.users.criteria import (
    OrganizationUserSearchCriteriaDTO,
    OrganizationUserSort,
    UserRoleFilter,
)
from app.identity.users.dtos import (
    OrganizationUserCreateDTO,
    OrganizationUserPatchDTO,
    OrganizationUserReadDTO,
    OrganizationUserReplaceDTO,
)
from app.identity.users.errors import (
    InactiveUserInvitationError,
    LastActiveOrganizationAdminError,
)
from app.openapi_tags import ORGANIZATION_ADMINISTRATION_V1_TAG
from app.security.authorization import require_organization_admin_permission
from app.security.dtos import UserPrincipalContext
from app.security.permissions import Permission


def organization_user_response(
    dto: OrganizationUserReadDTO,
) -> OrganizationUserResponse:
    """Convert organization-user service data to an HTTP response."""
    return OrganizationUserResponse(
        public_id=dto.public_id,
        email=dto.email,
        pending_email=dto.pending_email,
        first_name=dto.first_name,
        last_name=dto.last_name,
        is_active=dto.is_active,
        role=dto.role,
        email_verified=dto.email_verified,
        created_at=dto.created_at,
        updated_at=dto.updated_at,
    )


router = APIRouter(prefix="/users", tags=[ORGANIZATION_ADMINISTRATION_V1_TAG])
OrganizationUserListResponse = PaginatedResponse[OrganizationUserResponse]
OrganizationUsersReadDep = Annotated[
    UserPrincipalContext,
    Security(
        require_organization_admin_permission(Permission.ORGANIZATION_READ),
        scopes=[Permission.ORGANIZATION_READ.value],
    ),
]
OrganizationUsersWriteDep = Annotated[
    UserPrincipalContext,
    Security(
        require_organization_admin_permission(Permission.ORGANIZATION_WRITE),
        scopes=[Permission.ORGANIZATION_WRITE.value],
    ),
]
ORGANIZATION_USER_READ_AUTH_RESPONSES = app_error_responses(
    UnauthorizedError,
    SessionInvalidError,
    ForbiddenOperationError,
    descriptions={
        401: "Missing or invalid authentication.",
        403: (
            "Organization-admin role and the required permission are both required. "
            "An OAuth2 scope or server-operator role alone does not grant "
            "organization-admin access."
        ),
    },
)
ORGANIZATION_USER_WRITE_AUTH_RESPONSES = app_error_responses(
    UnauthorizedError,
    SessionInvalidError,
    ForbiddenOperationError,
    CSRFMissingCookieError,
    CSRFMissingHeaderError,
    CSRFCookieHeaderMismatchError,
    CSRFHeaderSessionMismatchError,
    descriptions={
        401: "Missing or invalid authentication.",
        403: (
            "Organization-admin role and the required permission are both required. "
            "An OAuth2 scope or server-operator role alone does not grant "
            "organization-admin access. Browser sessions must pass CSRF validation, "
            "and operator accounts cannot be mutated through this organization "
            "surface."
        ),
    },
)
ORGANIZATION_USER_NOT_FOUND_RESPONSE = app_error_responses(
    ObjectNotFoundError,
    descriptions={404: "User not found in the authenticated organization."},
)
ORGANIZATION_USER_CONFLICT_RESPONSE = app_error_responses(
    ObjectAlreadyExistsError,
    InactiveUserInvitationError,
    LastActiveOrganizationAdminError,
    UniqueViolationError,
    CheckViolationError,
    ForeignKeyViolationError,
    NotNullViolationError,
    descriptions={409: "The requested data conflicts with existing user state."},
)
ORGANIZATION_USER_LIST_RESPONSES = {
    **ORGANIZATION_USER_READ_AUTH_RESPONSES,
    **app_error_responses(
        StartDateAfterEndDateError,
        descriptions={400: "The created date range is invalid."},
    ),
}


@router.post(
    "",
    status_code=status.HTTP_201_CREATED,
    summary="Create or invite an organization user",
    responses={
        **ORGANIZATION_USER_WRITE_AUTH_RESPONSES,
        **ORGANIZATION_USER_CONFLICT_RESPONSE,
    },
)
async def add_user_to_organization(
    payload: OrganizationUserCreateRequest,
    users_service: OrganizationUsersServiceDep,
    _admin_ctx: OrganizationUsersWriteDep,
) -> OrganizationUserResponse:
    """Create a user in the authenticated administrator's organization."""
    dto = OrganizationUserCreateDTO(
        email=payload.email,
        password=payload.password,
        first_name=payload.first_name,
        last_name=payload.last_name,
        is_active=payload.is_active,
        role=payload.role,
    )
    result = await users_service.create(dto=dto)
    return organization_user_response(result)


@router.get(
    "",
    summary="List users in the authenticated organization",
    responses=ORGANIZATION_USER_LIST_RESPONSES,
)
async def list_users(  # noqa: PLR0913
    *,
    users_service: OrganizationUsersServiceDep,
    _admin_ctx: OrganizationUsersReadDep,
    q: Annotated[
        str | None,
        Query(description="Case-insensitive search across names and email addresses."),
    ] = None,
    sort: Annotated[
        OrganizationUserSort | None,
        Query(description="Sort field; values prefixed with '-' use descending order."),
    ] = None,
    role: Annotated[
        UserRoleFilter | None, Query(description="Organization membership role")
    ] = None,
    active: Annotated[
        bool | None, Query(description="Filter by active account state.")
    ] = None,
    email_verified: Annotated[
        bool | None, Query(description="Filter by verified email state.")
    ] = None,
    created_from: Annotated[
        date | None,
        Query(description="Include users created on or after this UTC date."),
    ] = None,
    created_to: Annotated[
        date | None,
        Query(description="Include users created on or before this UTC date."),
    ] = None,
    offset: Annotated[
        int, Query(ge=0, description="Number of matching users to skip.")
    ] = 0,
    limit: Annotated[
        int,
        Query(
            ge=1,
            le=DEFAULT_PAGE_LIMIT_MAX,
            description="Maximum number of users to return.",
        ),
    ] = 20,
) -> OrganizationUserListResponse:
    """List only users in the authenticated administrator's organization."""
    validate_date_range(start=created_from, end=created_to)
    page = await users_service.search(
        criteria=OrganizationUserSearchCriteriaDTO(
            q=q,
            sort=sort,
            role=role,
            active=active,
            email_verified=email_verified,
            created_from=created_from,
            created_to=created_to,
            offset=offset,
            limit=limit,
        )
    )
    return OrganizationUserListResponse(
        items=[organization_user_response(dto) for dto in page.items],
        limit=limit,
        offset=offset,
        total=page.total,
    )


@router.get(
    "/{user_id}",
    summary="Get a user in the authenticated organization",
    responses={
        **ORGANIZATION_USER_READ_AUTH_RESPONSES,
        **ORGANIZATION_USER_NOT_FOUND_RESPONSE,
    },
)
async def get_user(
    user_id: UserIdPath,
    users_service: OrganizationUsersServiceDep,
    _admin_ctx: OrganizationUsersReadDep,
) -> OrganizationUserResponse:
    """Retrieve a user using an organization-constrained query."""
    dto = await users_service.get(user_id=parse_user_id(user_id))
    return organization_user_response(dto)


@router.post(
    "/{user_id}/invitation",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Resend an organization user invitation",
    responses={
        **ORGANIZATION_USER_WRITE_AUTH_RESPONSES,
        **ORGANIZATION_USER_NOT_FOUND_RESPONSE,
        **ORGANIZATION_USER_CONFLICT_RESPONSE,
    },
)
async def resend_user_invitation(
    user_id: UserIdPath,
    users_service: OrganizationUsersServiceDep,
    _admin_ctx: OrganizationUsersWriteDep,
) -> None:
    """Resend an invitation without changing user lifecycle state."""
    await users_service.resend_invitation(user_id=parse_user_id(user_id))


@router.patch(
    "/{user_id}",
    summary="Patch a user in the authenticated organization",
    responses={
        **ORGANIZATION_USER_WRITE_AUTH_RESPONSES,
        **ORGANIZATION_USER_NOT_FOUND_RESPONSE,
        **ORGANIZATION_USER_CONFLICT_RESPONSE,
    },
)
async def patch_user(
    user_id: UserIdPath,
    payload: OrganizationUserPatchRequest,
    users_service: OrganizationUsersServiceDep,
    _admin_ctx: OrganizationUsersWriteDep,
) -> OrganizationUserResponse:
    """Patch supported lifecycle and administrative fields."""
    dto = OrganizationUserPatchDTO(**payload.model_dump(exclude_unset=True))
    result = await users_service.patch(
        user_id=parse_user_id(user_id),
        dto=dto,
    )
    return organization_user_response(result)


@router.put(
    "/{user_id}",
    summary="Replace a user in the authenticated organization",
    responses={
        **ORGANIZATION_USER_WRITE_AUTH_RESPONSES,
        **ORGANIZATION_USER_NOT_FOUND_RESPONSE,
        **ORGANIZATION_USER_CONFLICT_RESPONSE,
    },
)
async def replace_user(
    user_id: UserIdPath,
    payload: OrganizationUserReplaceRequest,
    users_service: OrganizationUsersServiceDep,
    _admin_ctx: OrganizationUsersWriteDep,
) -> OrganizationUserResponse:
    """Replace the organization-admin-managed representation within the organization."""
    dto = OrganizationUserReplaceDTO(
        email=payload.email,
        first_name=payload.first_name,
        last_name=payload.last_name,
        is_active=payload.is_active,
        role=payload.role,
    )
    result = await users_service.replace(
        user_id=parse_user_id(user_id),
        dto=dto,
    )
    return organization_user_response(result)


@router.delete(
    "/{user_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Delete a user in the authenticated organization",
    responses={
        **ORGANIZATION_USER_WRITE_AUTH_RESPONSES,
        **ORGANIZATION_USER_NOT_FOUND_RESPONSE,
        **ORGANIZATION_USER_CONFLICT_RESPONSE,
    },
)
async def delete_user(
    user_id: UserIdPath,
    users_service: OrganizationUsersServiceDep,
    _admin_ctx: OrganizationUsersWriteDep,
) -> Response:
    """Delete a user using the existing organization-scoped behavior."""
    await users_service.delete(user_id=parse_user_id(user_id))
    return Response(status_code=status.HTTP_204_NO_CONTENT)
