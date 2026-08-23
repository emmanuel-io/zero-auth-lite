"""Server-operator user administration API routes."""

from datetime import date
from typing import Annotated

from fastapi import APIRouter, Query, Response, Security, status

from app.api.dependencies.date_ranges import validate_date_range
from app.api.dependencies.ids import (
    parse_organization_id,
    parse_user_id,
    UserIdPath,
)
from app.api.error_responses import app_error_responses
from app.api.errors import StartDateAfterEndDateError
from app.api.schemas import (
    DEFAULT_PAGE_LIMIT_MAX,
    PaginatedResponse,
)
from app.api.v1.admin.users.schemas import (
    OperatorUserCreateRequest,
    OperatorUserPatchRequest,
    OperatorUserReplaceRequest,
    OperatorUserResponse,
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
from app.identity.dependencies import OperatorUsersServiceDep
from app.identity.public_ids import ORGANIZATION_ID_PATTERN
from app.identity.users.criteria import (
    OperatorUserSearchCriteriaDTO,
    OperatorUserSort,
    UserRoleFilter,
)
from app.identity.users.dtos import (
    OperatorUserCreateDTO,
    OperatorUserPatchDTO,
    OperatorUserReplaceDTO,
    UserReadDTO,
)
from app.identity.users.errors import (
    InactiveUserInvitationError,
    LastActiveOperatorError,
)
from app.security.authorization import require_operator_permission
from app.security.dtos import UserPrincipalContext
from app.security.permissions import Permission


router = APIRouter(prefix="/users")
OperatorUserListResponse = PaginatedResponse[OperatorUserResponse]
AUTH_ERROR_RESPONSES = app_error_responses(
    UnauthorizedError,
    SessionInvalidError,
    ForbiddenOperationError,
    descriptions={
        401: "Authentication is missing or invalid.",
        403: "Server-operator authority or the required scope is missing.",
    },
)
WRITE_AUTH_ERROR_RESPONSES = app_error_responses(
    UnauthorizedError,
    SessionInvalidError,
    ForbiddenOperationError,
    CSRFMissingCookieError,
    CSRFMissingHeaderError,
    CSRFCookieHeaderMismatchError,
    CSRFHeaderSessionMismatchError,
    descriptions={
        401: "Authentication is missing or invalid.",
        403: (
            "Server-operator authority, the required scope, and valid CSRF proof "
            "are required."
        ),
    },
)
USER_NOT_FOUND_RESPONSE = app_error_responses(
    ObjectNotFoundError,
    descriptions={404: "User or target organization not found."},
)
USER_LIST_ERROR_RESPONSES = {
    **AUTH_ERROR_RESPONSES,
    **app_error_responses(
        StartDateAfterEndDateError,
        descriptions={400: "The created date range is invalid."},
    ),
}
USER_CONFLICT_RESPONSE = app_error_responses(
    ObjectAlreadyExistsError,
    InactiveUserInvitationError,
    LastActiveOperatorError,
    UniqueViolationError,
    CheckViolationError,
    ForeignKeyViolationError,
    NotNullViolationError,
    descriptions={
        409: (
            "User data conflicts with existing data "
            "or a required operator lifecycle invariant."
        )
    },
)
OperatorUsersReadDep = Annotated[
    UserPrincipalContext,
    Security(
        require_operator_permission(Permission.USERS_READ),
        scopes=[Permission.USERS_READ.value],
    ),
]
OperatorUsersWriteDep = Annotated[
    UserPrincipalContext,
    Security(
        require_operator_permission(Permission.USERS_WRITE),
        scopes=[Permission.USERS_WRITE.value],
    ),
]


def operator_user_response(dto: UserReadDTO) -> OperatorUserResponse:
    """Convert user service data to its operator HTTP representation."""
    return OperatorUserResponse(
        public_id=dto.public_id,
        organization_id=dto.organization_id,
        email=dto.email,
        pending_email=dto.pending_email,
        first_name=dto.first_name,
        last_name=dto.last_name,
        is_active=dto.is_active,
        role=dto.role,
        is_operator=dto.is_operator,
        email_verified=dto.email_verified,
        created_at=dto.created_at,
        updated_at=dto.updated_at,
    )


@router.get(
    "",
    status_code=status.HTTP_200_OK,
    summary="List users across organizations",
    responses=USER_LIST_ERROR_RESPONSES,
)
async def list_users(  # noqa: PLR0913
    *,
    users_service: OperatorUsersServiceDep,
    _operator_ctx: OperatorUsersReadDep,
    q: Annotated[str | None, Query(description="Search name and email")] = None,
    sort: Annotated[
        OperatorUserSort | None,
        Query(description="Sort key; prefix '-' selects descending order."),
    ] = None,
    role: Annotated[
        UserRoleFilter | None, Query(description="Organization membership role")
    ] = None,
    operator: Annotated[
        bool | None, Query(description="Server-operator status")
    ] = None,
    active: Annotated[
        bool | None, Query(description="Filter by active account status.")
    ] = None,
    email_verified: Annotated[
        bool | None, Query(description="Filter by verified email status.")
    ] = None,
    organization_id: Annotated[
        str | None,
        Query(
            pattern=ORGANIZATION_ID_PATTERN,
            description="Serialized organization identifier",
        ),
    ] = None,
    created_from: Annotated[
        date | None, Query(description="Include users created on or after this date.")
    ] = None,
    created_to: Annotated[
        date | None, Query(description="Include users created on or before this date.")
    ] = None,
    offset: Annotated[int, Query(ge=0, description="Number of users to skip.")] = 0,
    limit: Annotated[
        int,
        Query(
            ge=1,
            le=DEFAULT_PAGE_LIMIT_MAX,
            description="Maximum users to return.",
        ),
    ] = 20,
) -> OperatorUserListResponse:
    """List users through the server-operator control plane."""
    validate_date_range(start=created_from, end=created_to)
    page = await users_service.search(
        criteria=OperatorUserSearchCriteriaDTO(
            q=q,
            sort=sort,
            role=role,
            operator=operator,
            active=active,
            email_verified=email_verified,
            organization_id=(
                parse_organization_id(organization_id)
                if organization_id is not None
                else None
            ),
            created_from=created_from,
            created_to=created_to,
            offset=offset,
            limit=limit,
        )
    )
    return OperatorUserListResponse(
        items=[operator_user_response(dto) for dto in page.items],
        offset=offset,
        limit=limit,
        total=page.total,
    )


@router.post(
    "",
    status_code=status.HTTP_201_CREATED,
    summary="Invite a user to any organization",
    description=(
        "Create an active, unverified user with an unusable generated credential "
        "and start the invitation workflow. The user sets their password and "
        "verifies their email by accepting the invitation. Email delivery depends "
        "on the configured notification provider."
    ),
    responses=WRITE_AUTH_ERROR_RESPONSES
    | USER_NOT_FOUND_RESPONSE
    | USER_CONFLICT_RESPONSE,
)
async def create_user(
    payload: OperatorUserCreateRequest,
    users_service: OperatorUsersServiceDep,
    _operator_ctx: OperatorUsersWriteDep,
) -> OperatorUserResponse:
    """Invite a user through the server-operator control plane."""
    dto = OperatorUserCreateDTO(
        email=payload.email,
        organization_id=parse_organization_id(payload.organization_id),
        first_name=payload.first_name,
        last_name=payload.last_name,
        role=payload.role,
        is_operator=payload.is_operator,
    )
    result = await users_service.create(dto=dto)
    return operator_user_response(result)


@router.get(
    "/{user_id}",
    status_code=status.HTTP_200_OK,
    summary="Get a user across organizations",
    responses=AUTH_ERROR_RESPONSES | USER_NOT_FOUND_RESPONSE,
)
async def get_user(
    user_id: UserIdPath,
    users_service: OperatorUsersServiceDep,
    _operator_ctx: OperatorUsersReadDep,
) -> OperatorUserResponse:
    """Retrieve a user through the server-operator control plane."""
    dto = await users_service.get(user_id=parse_user_id(user_id))
    return operator_user_response(dto)


@router.post(
    "/{user_id}/invitation",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Resend a user invitation",
    responses=WRITE_AUTH_ERROR_RESPONSES
    | USER_NOT_FOUND_RESPONSE
    | USER_CONFLICT_RESPONSE,
)
async def resend_user_invitation(
    user_id: UserIdPath,
    users_service: OperatorUsersServiceDep,
    _operator_ctx: OperatorUsersWriteDep,
) -> None:
    """Resend an invitation through the server-operator control plane."""
    await users_service.resend_invitation(user_id=parse_user_id(user_id))


@router.patch(
    "/{user_id}",
    status_code=status.HTTP_200_OK,
    summary="Patch a user across organizations",
    responses=WRITE_AUTH_ERROR_RESPONSES
    | USER_NOT_FOUND_RESPONSE
    | USER_CONFLICT_RESPONSE,
)
async def patch_user(
    user_id: UserIdPath,
    payload: OperatorUserPatchRequest,
    users_service: OperatorUsersServiceDep,
    _operator_ctx: OperatorUsersWriteDep,
) -> OperatorUserResponse:
    """Patch a user through the server-operator control plane."""
    values = payload.model_dump(exclude_unset=True, exclude={"organization_id"})
    if "organization_id" in payload.model_fields_set:
        values["organization_id"] = parse_organization_id(payload.organization_id or "")
    dto = OperatorUserPatchDTO(**values)
    result = await users_service.patch(
        user_id=parse_user_id(user_id),
        dto=dto,
    )
    return operator_user_response(result)


@router.put(
    "/{user_id}",
    status_code=status.HTTP_200_OK,
    summary="Replace a user across organizations",
    responses=WRITE_AUTH_ERROR_RESPONSES
    | USER_NOT_FOUND_RESPONSE
    | USER_CONFLICT_RESPONSE,
)
async def replace_user(
    user_id: UserIdPath,
    payload: OperatorUserReplaceRequest,
    users_service: OperatorUsersServiceDep,
    _operator_ctx: OperatorUsersWriteDep,
) -> OperatorUserResponse:
    """Replace a user through the server-operator control plane."""
    dto = OperatorUserReplaceDTO(
        organization_id=parse_organization_id(payload.organization_id),
        email=payload.email,
        first_name=payload.first_name,
        last_name=payload.last_name,
        is_active=payload.is_active,
        role=payload.role,
        is_operator=payload.is_operator,
        email_verified=payload.email_verified,
    )
    result = await users_service.replace(
        user_id=parse_user_id(user_id),
        dto=dto,
    )
    return operator_user_response(result)


@router.delete(
    "/{user_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Delete a user across organizations",
    responses=WRITE_AUTH_ERROR_RESPONSES
    | USER_NOT_FOUND_RESPONSE
    | USER_CONFLICT_RESPONSE,
)
async def delete_user(
    user_id: UserIdPath,
    users_service: OperatorUsersServiceDep,
    _operator_ctx: OperatorUsersWriteDep,
) -> Response:
    """Delete a user through the server-operator control plane."""
    await users_service.delete(user_id=parse_user_id(user_id))
    return Response(status_code=status.HTTP_204_NO_CONTENT)
