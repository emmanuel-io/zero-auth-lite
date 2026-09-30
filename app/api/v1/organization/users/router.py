"""Current-organization user administration API routes."""

from typing import Annotated

from fastapi import APIRouter, Response, Security, status

from app.api.dependencies.ids import UserIdPath
from app.api.schemas import PaginatedResponse
from app.api.v1.organization.users.mapping import organization_user_response
from app.api.v1.organization.users.openapi_responses import (
    ORGANIZATION_USER_CREATE_CONFLICT_RESPONSES,
    ORGANIZATION_USER_DELETE_CONFLICT_RESPONSES,
    ORGANIZATION_USER_INVITATION_CONFLICT_RESPONSES,
    ORGANIZATION_USER_LIST_RESPONSES,
    ORGANIZATION_USER_NOT_FOUND_RESPONSE,
    ORGANIZATION_USER_READ_AUTH_RESPONSES,
    ORGANIZATION_USER_UPDATE_CONFLICT_RESPONSES,
    ORGANIZATION_USER_WRITE_AUTH_RESPONSES,
)
from app.api.v1.organization.users.schemas import (
    OrganizationUserCreateRequest,
    OrganizationUserPatchRequest,
    OrganizationUserReplaceRequest,
    OrganizationUserResponse,
    OrganizationUserSearchQueryDep,
)
from app.identity.dependencies import OrganizationUsersServiceDep
from app.identity.users.criteria import (
    OrganizationUserSearchCriteriaDTO,
)
from app.identity.users.dtos import (
    OrganizationUserCreateDTO,
    OrganizationUserPatchDTO,
    OrganizationUserReplaceDTO,
)
from app.openapi_tags import ORGANIZATION_ADMINISTRATION_V1_TAG
from app.security.authorization import require_organization_admin_permission
from app.security.permissions import Permission
from app.security.principals import UserPrincipalContext


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


@router.post(
    "",
    status_code=status.HTTP_201_CREATED,
    summary="Create or invite an organization user",
    responses={
        **ORGANIZATION_USER_WRITE_AUTH_RESPONSES,
        **ORGANIZATION_USER_CREATE_CONFLICT_RESPONSES,
    },
)
async def create_organization_user(
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
async def list_users(
    *,
    users_service: OrganizationUsersServiceDep,
    _admin_ctx: OrganizationUsersReadDep,
    query: OrganizationUserSearchQueryDep,
) -> OrganizationUserListResponse:
    """List only users in the authenticated administrator's organization."""
    page = await users_service.search(
        criteria=OrganizationUserSearchCriteriaDTO(
            q=query.q,
            sort=query.sort,
            role=query.role,
            active=query.active,
            email_verified=query.email_verified,
            created_from=query.created_from,
            created_to=query.created_to,
            offset=query.offset,
            limit=query.limit,
        )
    )
    return OrganizationUserListResponse(
        items=[organization_user_response(dto) for dto in page.items],
        limit=query.limit,
        offset=query.offset,
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
    dto = await users_service.get(user_id=user_id)
    return organization_user_response(dto)


@router.post(
    "/{user_id}/invitation",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Resend an organization user invitation",
    responses={
        **ORGANIZATION_USER_WRITE_AUTH_RESPONSES,
        **ORGANIZATION_USER_NOT_FOUND_RESPONSE,
        **ORGANIZATION_USER_INVITATION_CONFLICT_RESPONSES,
    },
)
async def resend_user_invitation(
    user_id: UserIdPath,
    users_service: OrganizationUsersServiceDep,
    _admin_ctx: OrganizationUsersWriteDep,
) -> None:
    """Resend an invitation without changing user lifecycle state."""
    await users_service.resend_invitation(user_id=user_id)


@router.patch(
    "/{user_id}",
    summary="Patch a user in the authenticated organization",
    responses={
        **ORGANIZATION_USER_WRITE_AUTH_RESPONSES,
        **ORGANIZATION_USER_NOT_FOUND_RESPONSE,
        **ORGANIZATION_USER_UPDATE_CONFLICT_RESPONSES,
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
        user_id=user_id,
        dto=dto,
    )
    return organization_user_response(result)


@router.put(
    "/{user_id}",
    summary="Replace a user in the authenticated organization",
    responses={
        **ORGANIZATION_USER_WRITE_AUTH_RESPONSES,
        **ORGANIZATION_USER_NOT_FOUND_RESPONSE,
        **ORGANIZATION_USER_UPDATE_CONFLICT_RESPONSES,
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
        user_id=user_id,
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
        **ORGANIZATION_USER_DELETE_CONFLICT_RESPONSES,
    },
)
async def delete_user(
    user_id: UserIdPath,
    users_service: OrganizationUsersServiceDep,
    _admin_ctx: OrganizationUsersWriteDep,
) -> Response:
    """Delete a user using the existing organization-scoped behavior."""
    await users_service.delete(user_id=user_id)
    return Response(status_code=status.HTTP_204_NO_CONTENT)
