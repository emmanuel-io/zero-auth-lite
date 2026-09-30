"""Current-user OAuth2 session service DTOs."""

from dataclasses import dataclass
from datetime import datetime
from uuid import UUID

from app.oauth2.grants.types import OAuth2SessionGrantType


@dataclass(frozen=True, slots=True)
class UserOAuth2SessionDTO:
    """One active OAuth2 session owned by the current user."""

    public_id: UUID
    client_id: UUID
    client_name: str
    client_active: bool
    grant_type: OAuth2SessionGrantType
    scopes: list[str]
    created_at: datetime
    last_token_issued_at: datetime


@dataclass(frozen=True, slots=True)
class UserOAuth2SessionPageDTO:
    """One page of active OAuth2 sessions and the matching total count."""

    items: list[UserOAuth2SessionDTO]
    total: int
