"""Self-service current-user profile and account API routes."""

from typing import Annotated

from fastapi import APIRouter, Request, Response, Security, status

from app.api.v1.me.mapping import current_user_profile_response
from app.api.v1.me.openapi_responses import (
    ACCOUNT_DELETE_ERROR_RESPONSES,
    PASSWORD_CHANGE_ERROR_RESPONSES,
    PROFILE_AUTH_ERROR_RESPONSES,
    PROFILE_WRITE_ERROR_RESPONSES,
)
from app.api.v1.me.schemas import (
    CurrentUserPasswordChangeRequest,
    CurrentUserProfilePatchRequest,
    CurrentUserProfileResponse,
)
from app.browser_sessions.response_transport import (
    request_session_cookie_clear_on_success,
)
from app.identity.dependencies import BrowserUserSelfServiceDep, UserSelfServiceDep
from app.identity.users.dtos import (
    UserPasswordChangeDTO,
    UserSelfPatchDTO,
)
from app.openapi_tags import IDENTITY_PROFILE_V1_TAG
from app.security.authorization import require_permission
from app.security.permissions import Permission
from app.security.principals import UserPrincipalContext


router = APIRouter(tags=[IDENTITY_PROFILE_V1_TAG])
browser_account_router = APIRouter(tags=[IDENTITY_PROFILE_V1_TAG])


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


@browser_account_router.post(
    "/password",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Change current user password",
    operation_id="changeMePassword",
    responses=PASSWORD_CHANGE_ERROR_RESPONSES
    | {204: {"description": "Password changed and security sessions revoked."}},
)
async def change_password(
    request: Request,
    response: Response,
    payload: CurrentUserPasswordChangeRequest,
    user_service: BrowserUserSelfServiceDep,
) -> Response:
    """Verify the current password, replace it, and revoke security sessions."""
    dto = UserPasswordChangeDTO(
        current_password=payload.current_password,
        new_password=payload.new_password,
    )
    await user_service.change_password(data=dto)
    request_session_cookie_clear_on_success(request)
    response.status_code = status.HTTP_204_NO_CONTENT
    return response


@browser_account_router.delete(
    "",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Delete current identity profile",
    operation_id="deleteMe",
    responses=ACCOUNT_DELETE_ERROR_RESPONSES,
)
async def delete_me(
    request: Request,
    response: Response,
    user_service: BrowserUserSelfServiceDep,
) -> Response:
    """Delete the authenticated user's identity profile."""
    await user_service.delete()
    request_session_cookie_clear_on_success(request)
    response.status_code = status.HTTP_204_NO_CONTENT
    return response
