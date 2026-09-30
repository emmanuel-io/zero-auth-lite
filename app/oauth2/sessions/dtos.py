"""OAuth2 authorization-session persistence data shapes."""

from dataclasses import dataclass
from datetime import datetime
from uuid import UUID

from app.oauth2.grants.types import OAuth2SessionGrantType


@dataclass(frozen=True, slots=True)
class OAuth2SessionReadDTO:
    """Stored OAuth2 authorization session."""

    id: int
    public_id: UUID
    client_id: UUID
    grant_type: OAuth2SessionGrantType
    scope: str
    user_id: int | None
    organization_id: int | None
    created_at: datetime
    updated_at: datetime
    ended_at: datetime | None = None

    def is_active(self) -> bool:
        """Return whether the authorization session has not been ended."""
        return self.ended_at is None
