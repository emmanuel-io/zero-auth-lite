"""Server-operator browser-session maintenance API routes."""

from typing import Annotated, Literal

from fastapi import APIRouter, Query, Request, Security, status

from app.api.error_responses import app_error_responses
from app.browser_sessions.dependencies import SessionRevocationServiceDep
from app.browser_sessions.errors import (
    CSRFCookieHeaderMismatchError,
    CSRFHeaderSessionMismatchError,
    CSRFMissingCookieError,
    CSRFMissingHeaderError,
    SessionInvalidError,
)
from app.browser_sessions.response_transport import (
    request_session_cookie_clear_on_success,
)
from app.errors import ForbiddenOperationError, UnauthorizedError
from app.security.authorization import require_operator_permission
from app.security.dtos import AuthMethod, UserPrincipalContext
from app.security.permissions import Permission


router = APIRouter(prefix="/sessions")
SessionDeleteStatus = Literal["expired", "all"]
OperatorSessionsWriteDep = Annotated[
    UserPrincipalContext,
    Security(
        require_operator_permission(Permission.USERS_WRITE),
        scopes=[Permission.USERS_WRITE.value],
    ),
]


@router.delete(
    "",
    status_code=status.HTTP_200_OK,
    summary="Delete browser sessions across the server",
    description=(
        "Delete expired browser sessions or every browser session. Selecting "
        "`all` also revokes the operator's current browser session. The response "
        "is the number of deleted sessions."
    ),
    response_description="Number of browser sessions deleted.",
    responses=app_error_responses(
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
                "Server-operator authority, users:write, and valid CSRF proof "
                "are required."
            ),
        },
    ),
)
async def delete_sessions(
    request: Request,
    revocation_service: SessionRevocationServiceDep,
    operator_ctx: OperatorSessionsWriteDep,
    status: Annotated[
        SessionDeleteStatus,
        Query(description="Subset of browser sessions to delete"),
    ],
) -> int:
    """Delete browser sessions through the server-operator control plane."""
    if status == "expired":
        deleted = await revocation_service.cleanup_expired_sessions()
    else:
        deleted = await revocation_service.clear_all_sessions()
        if operator_ctx.auth_method == AuthMethod.SESSION:
            request_session_cookie_clear_on_success(request)
    return deleted
