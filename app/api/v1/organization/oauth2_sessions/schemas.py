"""HTTP schemas for current-organization OAuth2 session routes."""

from datetime import datetime
from typing import Annotated

from fastapi import Query
from pydantic import BaseModel, ConfigDict, Field, UUID4

from app.api.schemas import DEFAULT_PAGE_LIMIT_MAX
from app.oauth2.grants.types import OAuth2SessionGrantType


class OrganizationOAuth2SessionListQuery(BaseModel):
    """Query parameters for listing organization OAuth2 sessions."""

    model_config = ConfigDict(extra="forbid")

    client_id: UUID4 | None = Field(
        default=None,
        description="Return sessions issued to this OAuth2 client.",
    )
    grant_type: OAuth2SessionGrantType | None = Field(
        default=None,
        description="Return sessions created by this OAuth2 grant type.",
    )
    user_id: UUID4 | None = Field(
        default=None,
        description="Return sessions belonging to this organization user.",
    )
    active_only: bool = Field(
        default=True,
        description=(
            "Exclude expired families when true. Revoked families are deleted "
            "and are never returned."
        ),
    )
    offset: int = Field(
        default=0, ge=0, description="Number of matching sessions to skip."
    )
    limit: int = Field(
        default=100,
        ge=1,
        le=DEFAULT_PAGE_LIMIT_MAX,
        description="Maximum number of sessions to return.",
    )


OrganizationOAuth2SessionListQueryDep = Annotated[
    OrganizationOAuth2SessionListQuery, Query()
]


class OAuth2RevocationResponse(BaseModel):
    """Response payload for an organization OAuth2 revocation action."""

    revoked_sessions: int
    revoked_token_states: int


class OrganizationOAuth2SessionResponse(BaseModel):
    """Organization view of one OAuth2 token family/session."""

    id: UUID4
    client_id: UUID4
    grant_type: OAuth2SessionGrantType
    scopes: list[str]
    user_public_id: UUID4 | None = Field(
        default=None,
        serialization_alias="user_id",
    )
    organization_public_id: UUID4 = Field(serialization_alias="organization_id")
    active: bool
    access_expires_at: datetime
    refresh_expires_at: datetime | None
    created_at: datetime
    updated_at: datetime
