"""Map organization OAuth2 session data to HTTP responses."""

from app.api.v1.organization.oauth2_sessions.schemas import (
    OrganizationOAuth2SessionResponse,
)
from app.oauth2.organization_oauth2_sessions.dtos import OrganizationOAuth2SessionDTO


def organization_oauth2_session_response(
    dto: OrganizationOAuth2SessionDTO,
) -> OrganizationOAuth2SessionResponse:
    """Convert retained OAuth2 session data to an organization response."""
    return OrganizationOAuth2SessionResponse(
        id=dto.public_id,
        client_id=dto.client_id,
        grant_type=dto.grant_type,
        scopes=dto.scopes,
        user_public_id=dto.user_public_id,
        organization_public_id=dto.organization_public_id,
        active=dto.active,
        access_expires_at=dto.access_expires_at,
        refresh_expires_at=dto.refresh_expires_at,
        created_at=dto.created_at,
        updated_at=dto.updated_at,
    )
