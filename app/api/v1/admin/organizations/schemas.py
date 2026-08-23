"""HTTP schemas for server-operator organization administration routes."""

from typing import Annotated

from pydantic import BaseModel, ConfigDict, Field, field_serializer

from app.identity.organizations.types import OrganizationName
from app.identity.public_ids import format_organization_id, ORGANIZATION_ID_PATTERN
from app.public_ids import PublicId


class _OperatorOrganizationRequest(BaseModel):
    """Shared operator organization request fields."""

    model_config = ConfigDict(extra="forbid")

    name: Annotated[
        OrganizationName,
        Field(json_schema_extra={"example": "My Updated Organization"}),
    ]


class OperatorOrganizationCreateRequest(_OperatorOrganizationRequest):
    """Create-organization HTTP request."""


class OperatorOrganizationPatchRequest(_OperatorOrganizationRequest):
    """Patch-organization HTTP request."""


class OperatorOrganizationResponse(BaseModel):
    """Organization HTTP response."""

    name: OrganizationName
    public_id: PublicId = Field(
        serialization_alias="id",
        json_schema_extra={"pattern": ORGANIZATION_ID_PATTERN},
    )

    @field_serializer("public_id")
    def serialize_public_id(self, value: PublicId) -> str:
        """Serialize the public organization identifier."""
        return format_organization_id(value)
