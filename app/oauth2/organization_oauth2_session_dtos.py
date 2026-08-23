"""DTOs for organization-scoped OAuth2 session administration."""

from dataclasses import dataclass
from datetime import datetime

from app.public_ids import PublicId


@dataclass(frozen=True, slots=True)
class OAuth2RevocationResultDTO:
    """Counts produced by an OAuth2 revocation operation."""

    revoked_sessions: int
    revoked_token_pairs: int


@dataclass(frozen=True, slots=True)
class OrganizationOAuth2SessionDTO:
    """OAuth2 session metadata visible to organization administration."""

    public_id: PublicId
    client_id: str
    grant_type: str
    scope: str
    user_public_id: PublicId | None
    organization_public_id: PublicId
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
