"""HTTP schemas for current-organization metadata routes."""

from typing import Annotated

from pydantic import BaseModel, ConfigDict, Field, field_serializer

from app.identity.organizations.types import OrganizationName
from app.identity.public_ids import format_organization_id, ORGANIZATION_ID_PATTERN
from app.public_ids import PublicId


class CurrentOrganizationPatchRequest(BaseModel):
    """Current-organization patch HTTP request."""

    model_config = ConfigDict(extra="forbid")

    name: Annotated[
        OrganizationName,
        Field(json_schema_extra={"example": "My Updated Organization"}),
    ]


class CurrentOrganizationResponse(BaseModel):
    """Current-organization HTTP response."""

    name: OrganizationName
    public_id: PublicId = Field(
        serialization_alias="id",
        json_schema_extra={"pattern": ORGANIZATION_ID_PATTERN},
    )

    @field_serializer("public_id")
    def serialize_public_id(self, value: PublicId) -> str:
        """Serialize the public organization identifier."""
        return format_organization_id(value)
