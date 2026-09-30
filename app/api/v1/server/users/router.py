"""Server-wide user administration API routes."""

from typing import Annotated

from fastapi import APIRouter, Response, Security, status

from app.api.dependencies.ids import (
    UserIdPath,
)
from app.api.schemas import PaginatedResponse
from app.api.v1.server.users.mapping import server_user_response
from app.api.v1.server.users.openapi_responses import (
    AUTH_ERROR_RESPONSES,
    USER_CREATE_CONFLICT_RESPONSES,
    USER_DELETE_CONFLICT_RESPONSES,
    USER_INVITATION_CONFLICT_RESPONSES,
    USER_LIST_ERROR_RESPONSES,
    USER_NOT_FOUND_RESPONSE,
    USER_UPDATE_CONFLICT_RESPONSES,
    WRITE_AUTH_ERROR_RESPONSES,
)
from app.api.v1.server.users.schemas import (
    ServerUserCreateRequest,
    ServerUserPatchRequest,
    ServerUserReplaceRequest,
    ServerUserResponse,
    ServerUserSearchQueryDep,
)
from app.identity.dependencies import ServerUsersServiceDep
from app.identity.users.criteria import ServerUserSearchCriteriaDTO
from app.identity.users.dtos import (
    ServerUserCreateDTO,
    ServerUserPatchDTO,
    ServerUserReplaceDTO,
)
from app.security.authorization import require_operator_permission
from app.security.permissions import Permission
from app.security.principals import UserPrincipalContext


router = APIRouter(prefix="/users")
ServerUserListResponse = PaginatedResponse[ServerUserResponse]
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


@router.get(
    "",
    status_code=status.HTTP_200_OK,
    summary="List users across organizations",
    responses=USER_LIST_ERROR_RESPONSES,
)
async def list_users(
    *,
    users_service: ServerUsersServiceDep,
    _operator_ctx: OperatorUsersReadDep,
    query: ServerUserSearchQueryDep,
) -> ServerUserListResponse:
    """List users through the server control plane."""
    page = await users_service.search(
        criteria=ServerUserSearchCriteriaDTO(
            q=query.q,
            sort=query.sort,
            role=query.role,
            operator=query.operator,
            active=query.active,
            email_verified=query.email_verified,
            organization_id=(
                query.organization_id if query.organization_id is not None else None
            ),
            created_from=query.created_from,
            created_to=query.created_to,
            offset=query.offset,
            limit=query.limit,
        )
    )
    return ServerUserListResponse(
        items=[server_user_response(dto) for dto in page.items],
        offset=query.offset,
        limit=query.limit,
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
    | USER_CREATE_CONFLICT_RESPONSES,
)
async def create_user(
    payload: ServerUserCreateRequest,
    users_service: ServerUsersServiceDep,
    _operator_ctx: OperatorUsersWriteDep,
) -> ServerUserResponse:
    """Invite a user through the server control plane."""
    dto = ServerUserCreateDTO(
        email=payload.email,
        organization_id=payload.organization_id,
        first_name=payload.first_name,
        last_name=payload.last_name,
        role=payload.role,
        is_operator=payload.is_operator,
    )
    result = await users_service.create(dto=dto)
    return server_user_response(result)


@router.get(
    "/{user_id}",
    status_code=status.HTTP_200_OK,
    summary="Get a user across organizations",
    responses=AUTH_ERROR_RESPONSES | USER_NOT_FOUND_RESPONSE,
)
async def get_user(
    user_id: UserIdPath,
    users_service: ServerUsersServiceDep,
    _operator_ctx: OperatorUsersReadDep,
) -> ServerUserResponse:
    """Retrieve a user through the server control plane."""
    dto = await users_service.get(user_id=user_id)
    return server_user_response(dto)


@router.post(
    "/{user_id}/invitation",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Resend a user invitation",
    responses=WRITE_AUTH_ERROR_RESPONSES
    | USER_NOT_FOUND_RESPONSE
    | USER_INVITATION_CONFLICT_RESPONSES,
)
async def resend_user_invitation(
    user_id: UserIdPath,
    users_service: ServerUsersServiceDep,
    _operator_ctx: OperatorUsersWriteDep,
) -> None:
    """Resend an invitation through the server control plane."""
    await users_service.resend_invitation(user_id=user_id)


@router.patch(
    "/{user_id}",
    status_code=status.HTTP_200_OK,
    summary="Patch a user across organizations",
    responses=WRITE_AUTH_ERROR_RESPONSES
    | USER_NOT_FOUND_RESPONSE
    | USER_UPDATE_CONFLICT_RESPONSES,
)
async def patch_user(
    user_id: UserIdPath,
    payload: ServerUserPatchRequest,
    users_service: ServerUsersServiceDep,
    _operator_ctx: OperatorUsersWriteDep,
) -> ServerUserResponse:
    """Patch a user through the server control plane."""
    values = payload.model_dump(exclude_unset=True, exclude={"organization_id"})
    if "organization_id" in payload.model_fields_set:
        values["organization_id"] = payload.organization_id
    dto = ServerUserPatchDTO(**values)
    result = await users_service.patch(
        user_id=user_id,
        dto=dto,
    )
    return server_user_response(result)


@router.put(
    "/{user_id}",
    status_code=status.HTTP_200_OK,
    summary="Replace a user across organizations",
    responses=WRITE_AUTH_ERROR_RESPONSES
    | USER_NOT_FOUND_RESPONSE
    | USER_UPDATE_CONFLICT_RESPONSES,
)
async def replace_user(
    user_id: UserIdPath,
    payload: ServerUserReplaceRequest,
    users_service: ServerUsersServiceDep,
    _operator_ctx: OperatorUsersWriteDep,
) -> ServerUserResponse:
    """Replace a user through the server control plane."""
    dto = ServerUserReplaceDTO(
        organization_id=payload.organization_id,
        email=payload.email,
        first_name=payload.first_name,
        last_name=payload.last_name,
        is_active=payload.is_active,
        role=payload.role,
        is_operator=payload.is_operator,
        email_verified=payload.email_verified,
    )
    result = await users_service.replace(
        user_id=user_id,
        dto=dto,
    )
    return server_user_response(result)


@router.delete(
    "/{user_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Delete a user across organizations",
    responses=WRITE_AUTH_ERROR_RESPONSES
    | USER_NOT_FOUND_RESPONSE
    | USER_DELETE_CONFLICT_RESPONSES,
)
async def delete_user(
    user_id: UserIdPath,
    users_service: ServerUsersServiceDep,
    _operator_ctx: OperatorUsersWriteDep,
) -> Response:
    """Delete a user through the server control plane."""
    await users_service.delete(user_id=user_id)
    return Response(status_code=status.HTTP_204_NO_CONTENT)
