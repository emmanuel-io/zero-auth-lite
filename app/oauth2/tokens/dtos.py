"""OAuth2 token service and persistence data shapes."""

from dataclasses import dataclass
from datetime import datetime

from pydantic import BaseModel, ConfigDict, field_validator

from app.core.time import as_utc_aware
from app.oauth2.session_dtos import OAuth2SessionReadDTO
from app.oauth2.settings import OAuth2GrantType
from app.oauth2.tokens.access import AccessTokenPayload, TokenPairData
from app.public_ids import PublicId


@dataclass(frozen=True, slots=True)
class NewTokenSessionDTO:
    """Inputs shared when a grant starts a persisted token session."""

    access_payload: AccessTokenPayload
    grant_type: OAuth2GrantType
    client_id: str
    scope: str
    user_id: int | None
    organization_id: int | None
    include_refresh_token: bool


@dataclass(frozen=True, slots=True)
class IssuedTokenSessionDTO:
    """Issued token material paired with its persisted session identifier."""

    token_pair: TokenPairData
    session_id: int
    session_public_id: PublicId


class TokenPairUpdateDTO(BaseModel):
    """Token pair update data."""

    access_expires_at: datetime
    access_jti: str
    access_token: str
    refresh_expires_at: datetime
    refresh_token: str


class TokenPairReadDTO(BaseModel):
    """Internal token representation used by services on read."""

    access_expires_at: datetime
    access_jti: str
    access_token_hash: str
    refresh_expires_at: datetime | None = None
    refresh_token_hash: str | None = None
    session_id: int
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)
    """Pydantic model configuration."""

    @field_validator(
        "access_expires_at",
        "refresh_expires_at",
        "created_at",
        "updated_at",
    )
    @classmethod
    def normalize_database_datetimes(cls, value: datetime | None) -> datetime | None:
        """Normalize timestamps read from SQLite to aware UTC values."""
        return as_utc_aware(value) if value is not None else None


@dataclass(frozen=True, slots=True)
class OAuth2TokenFamilyReadDTO:
    """A persisted authorization session and its current token material."""

    session: OAuth2SessionReadDTO
    token_pair: TokenPairReadDTO
