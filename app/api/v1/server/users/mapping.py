"""Map server-wide user service data to HTTP responses."""

from app.api.v1.server.users.schemas import ServerUserResponse
from app.identity.users.dtos import UserReadDTO


def server_user_response(dto: UserReadDTO) -> ServerUserResponse:
    """Convert user service data to its server-wide HTTP representation."""
    return ServerUserResponse(
        public_id=dto.public_id,
        organization_id=dto.organization_public_id,
        email=dto.email,
        pending_email=dto.pending_email,
        first_name=dto.first_name,
        last_name=dto.last_name,
        is_active=dto.is_active,
        role=dto.role,
        is_operator=dto.is_operator,
        email_verified=dto.email_verified,
        created_at=dto.created_at,
        updated_at=dto.updated_at,
    )
