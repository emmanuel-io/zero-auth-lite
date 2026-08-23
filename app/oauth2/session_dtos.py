"""OAuth2 authorization-session persistence data shapes."""

from dataclasses import dataclass
from datetime import datetime

from app.public_ids import PublicId


@dataclass(frozen=True, slots=True)
class OAuth2SessionReadDTO:
    """Stored OAuth2 authorization session."""

    id: int
    public_id: PublicId
    client_id: str
    grant_type: str
    scope: str
    user_id: int | None
    organization_id: int | None
    created_at: datetime
    updated_at: datetime
    ended_at: datetime | None = None

    def is_active(self) -> bool:
        """Return whether the authorization session has not been ended."""
        return self.ended_at is None
