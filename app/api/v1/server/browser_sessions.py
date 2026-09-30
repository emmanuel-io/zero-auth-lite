"""Server-operator browser-session maintenance API routes."""

from typing import Annotated, Literal

from fastapi import APIRouter, Query, Request, Security, status

from app.api.error_responses import app_error_responses
from app.browser_sessions.errors import (
    BrowserSessionInvalidError,
    CSRF_ERRORS,
)
from app.browser_sessions.response_transport import (
    request_session_cookie_clear_on_success,
)
from app.browser_sessions.service_dependencies import BrowserSessionRevocationServiceDep
from app.core.errors.common import ForbiddenOperationError, UnauthorizedError
from app.security.authorization import require_operator_permission
from app.security.permissions import Permission
from app.security.principals import AuthenticationMechanism, UserPrincipalContext


router = APIRouter(prefix="/sessions")
SessionDeletionScope = Literal["inactive", "all"]
OperatorSessionsWriteDep = Annotated[
    UserPrincipalContext,
    Security(
        require_operator_permission(Permission.SESSIONS_WRITE),
        scopes=[Permission.SESSIONS_WRITE.value],
    ),
]


@router.delete(
    "",
    status_code=status.HTTP_200_OK,
    summary="Delete browser sessions across the server",
    description=(
        "Delete inactive browser sessions or every browser session. Inactive "
        "sessions are expired or revoked. Selecting "
        "`all` also revokes the operator's current browser session. The response "
        "is the number of deleted sessions."
    ),
    response_description="Number of browser sessions deleted.",
    responses=app_error_responses(
        UnauthorizedError,
        BrowserSessionInvalidError,
        ForbiddenOperationError,
        *CSRF_ERRORS,
        descriptions={
            401: "Authentication is missing or invalid.",
            403: (
                "Server-operator authority or sessions:write is missing, or a "
                "browser-session request lacks valid CSRF proof."
            ),
        },
    ),
)
async def delete_sessions(
    request: Request,
    revocation_service: BrowserSessionRevocationServiceDep,
    operator_ctx: OperatorSessionsWriteDep,
    scope: Annotated[
        SessionDeletionScope,
        Query(description="Subset of browser sessions to delete"),
    ],
) -> int:
    """Delete browser sessions through the server control plane."""
    if scope == "inactive":
        deleted = await revocation_service.cleanup_terminal_sessions()
    else:
        deleted = await revocation_service.delete_all_sessions()
        if (
            operator_ctx.authentication_mechanism
            is AuthenticationMechanism.BROWSER_SESSION
        ):
            request_session_cookie_clear_on_success(request)
    return deleted
