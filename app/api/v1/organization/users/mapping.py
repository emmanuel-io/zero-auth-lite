"""Map organization-user service data to HTTP responses."""

from app.api.v1.organization.users.schemas import OrganizationUserResponse
from app.identity.users.dtos import OrganizationUserReadDTO


def organization_user_response(
    dto: OrganizationUserReadDTO,
) -> OrganizationUserResponse:
    """Convert organization-user service data to an HTTP response."""
    return OrganizationUserResponse(
        public_id=dto.public_id,
        email=dto.email,
        pending_email=dto.pending_email,
        first_name=dto.first_name,
        last_name=dto.last_name,
        is_active=dto.is_active,
        role=dto.role,
        email_verified=dto.email_verified,
        created_at=dto.created_at,
        updated_at=dto.updated_at,
    )
