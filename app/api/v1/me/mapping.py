"""Map current-user service data to HTTP responses."""

from app.api.v1.me.schemas import (
    CurrentUserBrowserSessionResponse,
    CurrentUserOAuth2SessionResponse,
    CurrentUserOrganizationResponse,
    CurrentUserProfileResponse,
)
from app.browser_sessions.dtos import BrowserSessionReadDTO
from app.identity.users.dtos import UserSelfReadDTO
from app.oauth2.user_oauth2_sessions.dtos import UserOAuth2SessionDTO


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


def current_user_browser_session_response(
    *, session: BrowserSessionReadDTO, current_stored_session_id: str | None
) -> CurrentUserBrowserSessionResponse:
    """Convert stored browser-session metadata to an API-safe response."""
    return CurrentUserBrowserSessionResponse(
        id=session.public_id,
        current=current_stored_session_id == session.stored_session_id,
        active=session.is_active(),
        created_at=session.created_at,
        last_seen_at=session.last_seen_at,
        expires_at=session.expires_at,
        absolute_expires_at=session.absolute_expires_at,
        revoked_at=session.revoked_at,
        revoked_reason=session.revoked_reason,
    )


def current_user_oauth2_session_response(
    dto: UserOAuth2SessionDTO,
) -> CurrentUserOAuth2SessionResponse:
    """Convert an OAuth2 session DTO to its current-user response."""
    return CurrentUserOAuth2SessionResponse(
        id=dto.public_id,
        client_id=dto.client_id,
        client_name=dto.client_name,
        client_active=dto.client_active,
        grant_type=dto.grant_type,
        scopes=dto.scopes,
        created_at=dto.created_at,
        last_token_issued_at=dto.last_token_issued_at,
    )
