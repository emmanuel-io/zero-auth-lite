"""Map organization metadata service data to HTTP responses."""

from app.api.v1.organization.schemas import CurrentOrganizationResponse
from app.identity.organizations.dtos import OrganizationReadDTO


def current_organization_response(
    dto: OrganizationReadDTO,
) -> CurrentOrganizationResponse:
    """Convert current-organization service data to an HTTP response."""
    return CurrentOrganizationResponse(name=dto.name, public_id=dto.public_id)
