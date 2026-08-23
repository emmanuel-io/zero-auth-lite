"""Self-service current-user profile API routes."""

from typing import Annotated

from fastapi import APIRouter, Security, status

from app.api.v1.me.responses import (
    PROFILE_AUTH_ERROR_RESPONSES,
    PROFILE_WRITE_ERROR_RESPONSES,
)
from app.api.v1.me.schemas import (
    CurrentUserOrganizationResponse,
    CurrentUserProfilePatchRequest,
    CurrentUserProfileResponse,
)
from app.identity.dependencies import UserSelfServiceDep
from app.identity.users.dtos import UserSelfPatchDTO, UserSelfReadDTO
from app.openapi_tags import IDENTITY_PROFILE_V1_TAG
from app.security.authorization import require_permission
from app.security.dtos import UserPrincipalContext
from app.security.permissions import Permission


def current_user_profile_response(
    dto: UserSelfReadDTO,
) -> CurrentUserProfileResponse:
    """Convert current-user service data to its HTTP representation."""
    return CurrentUserProfileResponse(
        email=dto.email,
        pending_email=dto.pending_email,
        first_name=dto.first_name,
        last_name=dto.last_name,
        is_active=dto.is_active,
        role=dto.role,
        email_verified=dto.email_verified,
        organization=CurrentUserOrganizationResponse(name=dto.organization.name),
        created_at=dto.created_at,
        updated_at=dto.updated_at,
    )


router = APIRouter(tags=[IDENTITY_PROFILE_V1_TAG])


@router.get(
    "",
    status_code=status.HTTP_200_OK,
    summary="Get current identity profile",
    operation_id="getMe",
    responses=PROFILE_AUTH_ERROR_RESPONSES,
)
async def get_me(
    _principal: Annotated[
        UserPrincipalContext,
        Security(
            require_permission(Permission.PROFILE_READ),
            scopes=[Permission.PROFILE_READ.value],
        ),
    ],
    user_service: UserSelfServiceDep,
) -> CurrentUserProfileResponse:
    """Retrieve the authenticated user's identity profile."""
    dto = await user_service.read()
    return current_user_profile_response(dto)


@router.patch(
    "",
    status_code=status.HTTP_200_OK,
    summary="Partially update current identity profile",
    operation_id="patchMe",
    responses=PROFILE_WRITE_ERROR_RESPONSES,
)
async def patch_me(
    _principal: Annotated[
        UserPrincipalContext,
        Security(
            require_permission(Permission.PROFILE_WRITE),
            scopes=[Permission.PROFILE_WRITE.value],
        ),
    ],
    payload: CurrentUserProfilePatchRequest,
    user_service: UserSelfServiceDep,
) -> CurrentUserProfileResponse:
    """Patch the authenticated user's identity profile."""
    dto = UserSelfPatchDTO(**payload.model_dump(exclude_unset=True))
    result = await user_service.patch(data=dto)
    return current_user_profile_response(result)
