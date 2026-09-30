"""Map server-wide organization service data to HTTP responses."""

from app.api.v1.server.organizations.schemas import ServerOrganizationResponse
from app.identity.organizations.dtos import OrganizationReadDTO


def server_organization_response(
    dto: OrganizationReadDTO,
) -> ServerOrganizationResponse:
    """Convert organization service data to its server-wide HTTP representation."""
    return ServerOrganizationResponse(name=dto.name, public_id=dto.public_id)
