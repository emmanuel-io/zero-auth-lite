"""Current-user OAuth2 authorization API routes."""

from typing import Annotated

from fastapi import APIRouter, Path, Query, Response, status

from app.api.error_responses import app_error_responses
from app.api.schemas import DEFAULT_PAGE_LIMIT_MAX, PaginatedResponse
from app.api.v1.me.errors import OAuth2AuthorizationNotFoundError
from app.api.v1.me.responses import (
    BROWSER_SESSION_AUTH_ERROR_RESPONSES,
    BROWSER_SESSION_WRITE_AUTH_ERROR_RESPONSES,
)
from app.api.v1.me.schemas import CurrentUserOAuth2AuthorizationResponse
from app.browser_sessions.dependencies import CurrentBrowserUserContextDep
from app.oauth2.public_ids import (
    format_oauth2_session_id,
    OAUTH2_SESSION_ID_PATTERN,
)
from app.oauth2.user_authorizations.dependencies import OAuth2AuthorizationServiceDep
from app.openapi_tags import IDENTITY_PROFILE_V1_TAG


router = APIRouter(tags=[IDENTITY_PROFILE_V1_TAG])
CurrentUserOAuth2AuthorizationListResponse = PaginatedResponse[
    CurrentUserOAuth2AuthorizationResponse
]


@router.get(
    "/authorizations",
    status_code=status.HTTP_200_OK,
    summary="List current user's OAuth2 authorizations",
    operation_id="listMeAuthorizations",
    responses=BROWSER_SESSION_AUTH_ERROR_RESPONSES,
)
async def list_authorizations(
    response: Response,
    service: OAuth2AuthorizationServiceDep,
    user_ctx: CurrentBrowserUserContextDep,
    offset: Annotated[int, Query(ge=0, description="Number of grants to skip.")] = 0,
    limit: Annotated[int, Query(ge=1, le=DEFAULT_PAGE_LIMIT_MAX)] = 100,
) -> CurrentUserOAuth2AuthorizationListResponse:
    """List active OAuth2/OIDC client grants owned by the current user."""
    response.headers["Cache-Control"] = "no-store"
    page = await service.list_authorizations(
        user_ctx=user_ctx,
        offset=offset,
        limit=limit,
    )
    return CurrentUserOAuth2AuthorizationListResponse(
        items=[
            CurrentUserOAuth2AuthorizationResponse(
                id=format_oauth2_session_id(dto.public_id),
                client_id=dto.client_id,
                client_name=dto.client_name,
                client_active=dto.client_active,
                grant_type=dto.grant_type,
                scopes=dto.scopes,
                created_at=dto.created_at,
                last_token_issued_at=dto.last_token_issued_at,
            )
            for dto in page.items
        ],
        offset=offset,
        limit=limit,
        total=page.total,
    )


@router.delete(
    "/authorizations/{authorization_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Revoke one OAuth2 authorization owned by the current user",
    operation_id="deleteMeAuthorization",
    responses=BROWSER_SESSION_WRITE_AUTH_ERROR_RESPONSES
    | app_error_responses(
        OAuth2AuthorizationNotFoundError,
        descriptions={404: "OAuth2 authorization not found."},
    )
    | {204: {"description": "OAuth2 authorization revoked."}},
)
async def revoke_authorization(
    authorization_id: Annotated[
        str,
        Path(
            pattern=OAUTH2_SESSION_ID_PATTERN,
            description="OAuth2 authorization identifier",
            examples=["oas_001P018WN3AT0"],
        ),
    ],
    service: OAuth2AuthorizationServiceDep,
    user_ctx: CurrentBrowserUserContextDep,
) -> None:
    """Revoke one OAuth2/OIDC client grant owned by the current user."""
    revoked = await service.revoke_authorization(
        authorization_id=authorization_id,
        user_ctx=user_ctx,
    )
    if not revoked:
        raise OAuth2AuthorizationNotFoundError
