"""Current-user OAuth2 authorization service DTOs."""

from dataclasses import dataclass
from datetime import datetime

from app.public_ids import PublicId


@dataclass(frozen=True, slots=True)
class OAuth2AuthorizationDTO:
    """One active client grant owned by the current user."""

    public_id: PublicId
    client_id: str
    client_name: str
    client_active: bool
    grant_type: str
    scopes: list[str]
    created_at: datetime
    last_token_issued_at: datetime


@dataclass(frozen=True, slots=True)
class OAuth2AuthorizationPageDTO:
    """One page of active client grants and the matching total count."""

    items: list[OAuth2AuthorizationDTO]
    total: int
