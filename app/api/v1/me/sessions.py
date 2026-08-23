"""Current-user account routes that require a browser session."""

from logging import getLogger
from typing import Annotated

from fastapi import APIRouter, Path, Query, Request, Response, status

from app.api.error_responses import app_error_responses
from app.api.schemas import DEFAULT_PAGE_LIMIT_MAX
from app.api.v1.me.errors import (
    BrowserSessionNotFoundError,
    CurrentSessionRequiresLogoutError,
)
from app.api.v1.me.responses import (
    ACCOUNT_DELETE_ERROR_RESPONSES,
    BROWSER_SESSION_AUTH_ERROR_RESPONSES,
    BROWSER_SESSION_WRITE_AUTH_ERROR_RESPONSES,
    PASSWORD_CHANGE_ERROR_RESPONSES,
)
from app.api.v1.me.schemas import (
    CurrentUserBrowserSessionResponse,
    CurrentUserPasswordChangeRequest,
)
from app.browser_sessions.cookies import get_session_cookie
from app.browser_sessions.dependencies import (
    CurrentBrowserUserContextDep,
    SessionLifecycleServiceDep,
    SessionRevocationServiceDep,
)
from app.browser_sessions.dtos import SessionReadDTO
from app.browser_sessions.public_ids import (
    BROWSER_SESSION_ID_PATTERN,
    format_browser_session_id,
    parse_browser_session_id,
)
from app.browser_sessions.response_transport import (
    request_session_cookie_clear_on_success,
)
from app.identity.dependencies import BrowserUserSelfServiceDep
from app.identity.public_ids import format_user_id
from app.identity.users.dtos import UserPasswordChangeDTO
from app.openapi_tags import IDENTITY_PROFILE_V1_TAG
from app.settings.dependencies import SessionSettingsDep


router = APIRouter(tags=[IDENTITY_PROFILE_V1_TAG])
logger = getLogger(__name__)


def _to_session_response(
    *, session: SessionReadDTO, current_stored_session_id: str | None
) -> CurrentUserBrowserSessionResponse:
    """Convert stored session metadata into an API-safe response."""
    return CurrentUserBrowserSessionResponse(
        id=format_browser_session_id(session.public_id),
        current=current_stored_session_id == session.stored_session_id,
        active=session.is_active(),
        created_at=session.created_at,
        last_seen_at=session.last_seen_at,
        expires_at=session.expires_at,
        absolute_expires_at=session.absolute_expires_at,
        revoked_at=session.revoked_at,
        revoked_reason=session.revoked_reason,
    )


async def list_sessions(  # noqa: PLR0913
    *,
    lifecycle_service: SessionLifecycleServiceDep,
    revocation_service: SessionRevocationServiceDep,
    request: Request,
    user_ctx: CurrentBrowserUserContextDep,
    session_settings: SessionSettingsDep,
    active_only: Annotated[bool, Query()] = True,
    limit: Annotated[int, Query(ge=1, le=DEFAULT_PAGE_LIMIT_MAX)] = 50,
) -> list[CurrentUserBrowserSessionResponse]:
    """List browser sessions owned by the current user."""
    sessions = await revocation_service.list_user_sessions(
        user_id=user_ctx.user_id,
        active_only=active_only,
        limit=limit,
    )
    current_session_id = get_session_cookie(request, session_settings)
    current_stored_session_id = (
        lifecycle_service.stored_session_id(session_id=current_session_id)
        if current_session_id is not None
        else None
    )
    return [
        _to_session_response(
            session=session,
            current_stored_session_id=current_stored_session_id,
        )
        for session in sessions
    ]


async def revoke_session(
    session_id: Annotated[
        str,
        Path(
            pattern=BROWSER_SESSION_ID_PATTERN,
            description="Browser session identifier",
            examples=["ses_001P018WN3AT0"],
        ),
    ],
    lifecycle_service: SessionLifecycleServiceDep,
    revocation_service: SessionRevocationServiceDep,
    user_ctx: CurrentBrowserUserContextDep,
) -> None:
    """Revoke another browser session owned by the current user."""
    current_session_id = user_ctx.session_id
    public_id = parse_browser_session_id(session_id)
    current_session = await lifecycle_service.get_session_csrf_state(
        session_id=current_session_id
    )
    if public_id == current_session.public_id:
        raise CurrentSessionRequiresLogoutError
    revoked = await revocation_service.revoke_user_session_by_public_id(
        public_id=public_id,
        user_id=user_ctx.user_id,
        reason="user_revoked",
    )
    if not revoked:
        raise BrowserSessionNotFoundError
    logger.info(
        (
            "event=browser_session_revocation outcome=attempted subject_id=%s "
            "session_id=%s reason=user_revoked revoked_sessions=1"
        ),
        format_user_id(user_ctx.user_public_id)
        if user_ctx.user_public_id
        else "unknown",
        session_id,
    )


@router.post(
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


@router.delete(
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
