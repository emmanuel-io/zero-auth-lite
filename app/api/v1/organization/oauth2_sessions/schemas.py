"""HTTP schemas for current-organization OAuth2 session routes."""

from datetime import datetime

from pydantic import BaseModel, Field, field_serializer

from app.identity.public_ids import (
    format_organization_id,
    format_user_id,
    ORGANIZATION_ID_PATTERN,
    USER_ID_PATTERN,
)
from app.oauth2.public_ids import format_oauth2_session_id, OAUTH2_SESSION_ID_PATTERN
from app.public_ids import PublicId


class OAuth2RevocationResponse(BaseModel):
    """Response payload for an organization OAuth2 revocation action."""

    revoked_sessions: int
    revoked_token_pairs: int


class OAuth2SessionResponse(BaseModel):
    """Response payload for an OAuth2 token family/session."""

    public_id: PublicId = Field(
        serialization_alias="session_id",
        json_schema_extra={"pattern": OAUTH2_SESSION_ID_PATTERN},
    )
    client_id: str
    grant_type: str
    scope: str
    user_public_id: PublicId | None = Field(
        default=None,
        serialization_alias="user_id",
        json_schema_extra={"pattern": USER_ID_PATTERN},
    )
    organization_public_id: PublicId = Field(
        serialization_alias="organization_id",
        json_schema_extra={"pattern": ORGANIZATION_ID_PATTERN},
    )
    active: bool
    access_expires_at: datetime
    refresh_expires_at: datetime | None
    created_at: datetime
    updated_at: datetime

    @field_serializer("public_id")
    def serialize_public_id(self, value: PublicId) -> str:
        """Serialize the public OAuth2 session identifier."""
        return format_oauth2_session_id(value)

    @field_serializer("user_public_id")
    def serialize_user_public_id(self, value: PublicId | None) -> str | None:
        """Serialize the public user identifier when present."""
        return format_user_id(value) if value is not None else None

    @field_serializer("organization_public_id")
    def serialize_organization_public_id(self, value: PublicId) -> str:
        """Serialize the public organization identifier."""
        return format_organization_id(value)
