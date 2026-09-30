"""HTTP schemas for server-wide organization administration routes."""

from typing import Annotated

from fastapi import Query
from pydantic import BaseModel, ConfigDict, Field, UUID4

from app.api.schemas import DEFAULT_PAGE_LIMIT_MAX
from app.identity.organizations.types import OrganizationName


class ServerOrganizationListQuery(BaseModel):
    """Query parameters for listing organizations."""

    model_config = ConfigDict(extra="forbid")

    offset: int = Field(default=0, ge=0)
    limit: int = Field(default=20, ge=1, le=DEFAULT_PAGE_LIMIT_MAX)


ServerOrganizationListQueryDep = Annotated[ServerOrganizationListQuery, Query()]


class _ServerOrganizationRequest(BaseModel):
    """Shared operator organization request fields."""

    model_config = ConfigDict(extra="forbid")

    name: Annotated[
        OrganizationName,
        Field(json_schema_extra={"example": "My Updated Organization"}),
    ]


class ServerOrganizationCreateRequest(_ServerOrganizationRequest):
    """Create-organization HTTP request."""


class ServerOrganizationPatchRequest(_ServerOrganizationRequest):
    """Patch-organization HTTP request."""


class ServerOrganizationResponse(BaseModel):
    """Organization HTTP response."""

    name: OrganizationName
    public_id: UUID4 = Field(serialization_alias="id")
