"""Actor-independent behavior for user security-session management pages."""

from dataclasses import dataclass
from enum import StrEnum
from typing import assert_never, Protocol
from uuid import UUID

from fastapi import Request, Response

from app.browser_sessions.enums import BrowserSessionRevocationReason
from app.browser_sessions.lifecycle import BrowserSessionLifecycleService
from app.browser_sessions.response_transport import (
    request_session_cookie_clear_on_success,
)
from app.browser_sessions.revocation import BrowserSessionRevocationService
from app.identity.users.dtos import UserSessionTargetDTO
from app.security.principals import BrowserUserPrincipalContext
from app.security.session_revocation import SecuritySessionRevocationService
from app.web.management.notices import ManagementNotice
from app.web.management.responses import (
    authentication_navigation_url,
    mutation_success,
    render_management_page,
)


class UserSessionOperation(StrEnum):
    """Operations available for one user's security sessions."""

    DELETE_BROWSER = "delete_browser"
    DELETE_OAUTH2 = "delete_oauth2"
    REVOKE_ALL = "revoke_all"


class UserSessionTargetReader(Protocol):
    """Resolve a user already authorized in the caller's actor scope."""

    async def get_session_target(self, *, user_id: UUID) -> UserSessionTargetDTO:
        """Return the internal identity needed by session operations."""
        ...


@dataclass(frozen=True, slots=True)
class UserSessionConfirmation:
    """Presentation details for one user-session operation."""

    heading: str
    message: str
    submit_label: str
    action_suffix: str


def _confirmation(
    operation: UserSessionOperation, *, email: str
) -> UserSessionConfirmation:
    """Return confirmation-page content for one user-session operation."""
    match operation:
        case UserSessionOperation.DELETE_BROWSER:
            return UserSessionConfirmation(
                heading="Delete user browser sessions?",
                message=(
                    f"This permanently deletes browser sessions belonging to {email}. "
                    "OAuth2 sessions are not affected."
                ),
                submit_label="Delete browser sessions",
                action_suffix="browser/delete",
            )
        case UserSessionOperation.DELETE_OAUTH2:
            return UserSessionConfirmation(
                heading="Delete user OAuth2 sessions?",
                message=(
                    f"This permanently deletes OAuth2 sessions belonging to {email}. "
                    "Browser sessions are not affected."
                ),
                submit_label="Delete OAuth2 sessions",
                action_suffix="oauth2/delete",
            )
        case UserSessionOperation.REVOKE_ALL:
            return UserSessionConfirmation(
                heading="Revoke all user sessions?",
                message=f"This ends browser and OAuth2 sessions belonging to {email}.",
                submit_label="Revoke all sessions",
                action_suffix="revoke",
            )
    assert_never(operation)


async def render_user_session_confirmation(  # noqa: PLR0913
    *,
    request: Request,
    lifecycle_service: BrowserSessionLifecycleService,
    user_ctx: BrowserUserPrincipalContext,
    users_service: UserSessionTargetReader,
    target_public_id: UUID,
    user_path: str,
    operation: UserSessionOperation,
) -> Response:
    """Resolve the authorized target and render its confirmation page."""
    target = await users_service.get_session_target(user_id=target_public_id)
    content = _confirmation(operation, email=target.email)
    return await render_management_page(
        request,
        lifecycle_service,
        user_ctx,
        "management/confirm.html",
        heading=content.heading,
        message=content.message,
        action=f"{user_path}/sessions/{content.action_suffix}",
        cancel_url=user_path,
        submit_label=content.submit_label,
    )


async def delete_user_browser_sessions(  # noqa: PLR0913
    *,
    request: Request,
    users_service: UserSessionTargetReader,
    revocation_service: BrowserSessionRevocationService,
    target_public_id: UUID,
    current_user_id: int,
    user_path: str,
) -> Response:
    """Resolve the authorized target and delete its browser sessions."""
    target = await users_service.get_session_target(user_id=target_public_id)
    target_user_id = target.internal_user_id
    await revocation_service.delete_user_sessions(user_id=target_user_id)
    if target_user_id == current_user_id:
        request_session_cookie_clear_on_success(request)
    destination = (
        authentication_navigation_url(request)
        if target_user_id == current_user_id
        else user_path
    )
    return mutation_success(
        request,
        destination,
        notice=ManagementNotice.BROWSER_SESSIONS_DELETED,
    )


async def delete_user_oauth2_sessions(
    *,
    request: Request,
    users_service: UserSessionTargetReader,
    revocation_service: SecuritySessionRevocationService,
    target_public_id: UUID,
    user_path: str,
) -> Response:
    """Resolve the authorized target and delete its OAuth2 sessions."""
    target = await users_service.get_session_target(user_id=target_public_id)
    await revocation_service.clear_user_oauth2_sessions(user_id=target.internal_user_id)
    return mutation_success(
        request,
        user_path,
        notice=ManagementNotice.OAUTH2_SESSIONS_DELETED,
    )


async def revoke_user_sessions(  # noqa: PLR0913
    *,
    request: Request,
    users_service: UserSessionTargetReader,
    revocation_service: SecuritySessionRevocationService,
    target_public_id: UUID,
    current_user_id: int,
    user_path: str,
    browser_reason: BrowserSessionRevocationReason,
) -> Response:
    """Resolve the authorized target and revoke its complete session authority."""
    target = await users_service.get_session_target(user_id=target_public_id)
    target_user_id = target.internal_user_id
    await revocation_service.revoke_user_security_sessions(
        user_id=target_user_id,
        browser_reason=browser_reason,
    )
    if target_user_id == current_user_id:
        request_session_cookie_clear_on_success(request)
    destination = (
        authentication_navigation_url(request)
        if target_user_id == current_user_id
        else user_path
    )
    return mutation_success(
        request,
        destination,
        notice=ManagementNotice.USER_SESSIONS_REVOKED,
    )
