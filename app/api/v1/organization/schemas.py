"""HTTP schemas for current-organization metadata routes."""

from typing import Annotated

from pydantic import BaseModel, ConfigDict, Field, UUID4

from app.identity.organizations.types import OrganizationName


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
    public_id: UUID4 = Field(serialization_alias="id")
