"""Current-user OAuth2 session API routes."""

from typing import Annotated

from fastapi import APIRouter, Path, status
from pydantic import UUID4

from app.api.error_responses import app_error_responses
from app.api.schemas import PaginatedResponse
from app.api.v1.me.errors import OAuth2SessionNotFoundError
from app.api.v1.me.mapping import current_user_oauth2_session_response
from app.api.v1.me.openapi_responses import (
    BROWSER_SESSION_AUTH_ERROR_RESPONSES,
    BROWSER_SESSION_WRITE_AUTH_ERROR_RESPONSES,
)
from app.api.v1.me.schemas import (
    CurrentUserOAuth2SessionListQueryDep,
    CurrentUserOAuth2SessionResponse,
)
from app.browser_sessions.dependencies import CurrentBrowserUserContextDep
from app.oauth2.user_oauth2_sessions.dependencies import UserOAuth2SessionServiceDep
from app.openapi_tags import IDENTITY_PROFILE_V1_TAG


router = APIRouter(tags=[IDENTITY_PROFILE_V1_TAG])
CurrentUserOAuth2SessionListResponse = PaginatedResponse[
    CurrentUserOAuth2SessionResponse
]


@router.get(
    "/oauth2/sessions",
    status_code=status.HTTP_200_OK,
    summary="List current user's OAuth2 sessions",
    operation_id="listMeOAuth2Sessions",
    responses=BROWSER_SESSION_AUTH_ERROR_RESPONSES,
)
async def list_oauth2_sessions(
    service: UserOAuth2SessionServiceDep,
    user_ctx: CurrentBrowserUserContextDep,
    query: CurrentUserOAuth2SessionListQueryDep,
) -> CurrentUserOAuth2SessionListResponse:
    """List active OAuth2 sessions owned by the current user."""
    page = await service.list_sessions(
        user_ctx=user_ctx,
        offset=query.offset,
        limit=query.limit,
    )
    return CurrentUserOAuth2SessionListResponse(
        items=[current_user_oauth2_session_response(dto) for dto in page.items],
        offset=query.offset,
        limit=query.limit,
        total=page.total,
    )


@router.delete(
    "/oauth2/sessions/{session_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Revoke one OAuth2 session owned by the current user",
    operation_id="deleteMeOAuth2Session",
    responses=BROWSER_SESSION_WRITE_AUTH_ERROR_RESPONSES
    | app_error_responses(
        OAuth2SessionNotFoundError,
        descriptions={404: "OAuth2 session not found."},
    )
    | {204: {"description": "OAuth2 session revoked."}},
)
async def revoke_oauth2_session(
    session_id: Annotated[
        UUID4,
        Path(
            description="OAuth2 session identifier",
            examples=["550e8400-e29b-41d4-a716-446655440000"],
        ),
    ],
    service: UserOAuth2SessionServiceDep,
    user_ctx: CurrentBrowserUserContextDep,
) -> None:
    """Revoke one OAuth2 session owned by the current user."""
    revoked = await service.revoke_session(
        session_id=session_id,
        user_ctx=user_ctx,
    )
    if not revoked:
        raise OAuth2SessionNotFoundError
