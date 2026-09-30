"""Current-user browser-session administration API routes."""

from logging import getLogger
from typing import Annotated

from fastapi import APIRouter, Path, Request, status
from pydantic import UUID4

from app.api.error_responses import app_error_responses
from app.api.schemas import PaginatedResponse
from app.api.v1.me.errors import (
    BrowserSessionNotFoundError,
    CurrentSessionRequiresLogoutError,
)
from app.api.v1.me.mapping import current_user_browser_session_response
from app.api.v1.me.openapi_responses import (
    BROWSER_SESSION_AUTH_ERROR_RESPONSES,
    BROWSER_SESSION_WRITE_AUTH_ERROR_RESPONSES,
)
from app.api.v1.me.schemas import (
    CurrentUserBrowserSessionListQueryDep,
    CurrentUserBrowserSessionResponse,
)
from app.browser_sessions.cookies import get_session_cookie
from app.browser_sessions.dependencies import (
    CurrentBrowserUserContextDep,
)
from app.browser_sessions.enums import BrowserSessionRevocationReason
from app.browser_sessions.service_dependencies import (
    BrowserSessionLifecycleServiceDep,
    BrowserSessionRevocationServiceDep,
)
from app.openapi_tags import IDENTITY_PROFILE_V1_TAG
from app.settings.dependencies import BrowserSessionSettingsDep


router = APIRouter(tags=[IDENTITY_PROFILE_V1_TAG])
logger = getLogger(__name__)
CurrentUserBrowserSessionListResponse = PaginatedResponse[
    CurrentUserBrowserSessionResponse
]


async def list_sessions(  # noqa: PLR0913
    *,
    lifecycle_service: BrowserSessionLifecycleServiceDep,
    revocation_service: BrowserSessionRevocationServiceDep,
    request: Request,
    user_ctx: CurrentBrowserUserContextDep,
    session_settings: BrowserSessionSettingsDep,
    query: CurrentUserBrowserSessionListQueryDep,
) -> CurrentUserBrowserSessionListResponse:
    """List browser sessions owned by the current user."""
    page = await revocation_service.list_user_sessions(
        user_id=user_ctx.user_id,
        active_only=query.active_only,
        offset=query.offset,
        limit=query.limit,
    )
    current_session_id = get_session_cookie(request, session_settings)
    current_stored_session_id = (
        lifecycle_service.stored_session_id(session_id=current_session_id)
        if current_session_id is not None
        else None
    )
    return CurrentUserBrowserSessionListResponse(
        items=[
            current_user_browser_session_response(
                session=session,
                current_stored_session_id=current_stored_session_id,
            )
            for session in page.items
        ],
        offset=query.offset,
        limit=query.limit,
        total=page.total,
    )


async def revoke_session(
    session_id: Annotated[
        UUID4,
        Path(
            description="Browser session identifier",
            examples=["550e8400-e29b-41d4-a716-446655440000"],
        ),
    ],
    lifecycle_service: BrowserSessionLifecycleServiceDep,
    revocation_service: BrowserSessionRevocationServiceDep,
    user_ctx: CurrentBrowserUserContextDep,
) -> None:
    """Revoke another browser session owned by the current user."""
    current_session_id = user_ctx.raw_session_id
    current_session = await lifecycle_service.get_session_csrf_state(
        session_id=current_session_id
    )
    if session_id == current_session.public_id:
        raise CurrentSessionRequiresLogoutError
    revoked = await revocation_service.revoke_user_session_by_public_id(
        public_id=session_id,
        user_id=user_ctx.user_id,
        reason=BrowserSessionRevocationReason.USER_REVOKED,
    )
    if not revoked:
        raise BrowserSessionNotFoundError
    logger.info(
        (
            "event=browser_session_revocation outcome=attempted subject_id=%s "
            "session_id=%s reason=user_revoked revoked_sessions=1"
        ),
        str(user_ctx.user_public_id),
        session_id,
    )


router.add_api_route(
    "/sessions",
    list_sessions,
    methods=["GET"],
    summary="List current user's browser sessions",
    operation_id="listMeSessions",
    responses=BROWSER_SESSION_AUTH_ERROR_RESPONSES,
)
router.add_api_route(
    "/sessions/{session_id}",
    revoke_session,
    methods=["DELETE"],
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Revoke another browser session owned by the current user",
    operation_id="deleteMeSession",
    responses=BROWSER_SESSION_WRITE_AUTH_ERROR_RESPONSES
    | app_error_responses(
        BrowserSessionNotFoundError,
        CurrentSessionRequiresLogoutError,
        descriptions={
            404: "Browser session not found.",
            409: "Current session must be ended through logout.",
        },
    )
    | {204: {"description": "Browser session revoked."}},
)
