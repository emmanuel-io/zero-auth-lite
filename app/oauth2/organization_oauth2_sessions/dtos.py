"""Data transfer objects for organization-scoped OAuth2 sessions."""

from dataclasses import dataclass
from datetime import datetime
from uuid import UUID

from app.oauth2.grants.types import OAuth2SessionGrantType


@dataclass(frozen=True, slots=True)
class OAuth2RevocationResultDTO:
    """Counts produced by an OAuth2 revocation operation."""

    revoked_sessions: int
    revoked_token_states: int


@dataclass(frozen=True, slots=True)
class OrganizationOAuth2SessionDTO:
    """OAuth2 session metadata visible to organization administration."""

    public_id: UUID
    client_id: UUID
    grant_type: OAuth2SessionGrantType
    scopes: list[str]
    user_public_id: UUID | None
    organization_public_id: UUID
    active: bool
    access_expires_at: datetime
    refresh_expires_at: datetime | None
    created_at: datetime
    updated_at: datetime


@dataclass(frozen=True, slots=True)
class OrganizationOAuth2SessionPageDTO:
    """One page of organization OAuth2 sessions and its total count."""

    items: list[OrganizationOAuth2SessionDTO]
    total: int
