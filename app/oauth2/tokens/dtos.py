"""OAuth2 token service and persistence data shapes."""

from dataclasses import dataclass
from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, ConfigDict, field_validator

from app.core.time import as_utc_aware
from app.oauth2.grants.types import OAuth2SessionGrantType
from app.oauth2.principal_types import PrincipalType, session_principal_type
from app.oauth2.sessions.dtos import OAuth2SessionReadDTO
from app.oauth2.tokens.access import AccessTokenPayload, IssuedTokens


@dataclass(frozen=True, slots=True)
class NewTokenSessionDTO:
    """Inputs shared when a grant starts a persisted token session."""

    access_payload: AccessTokenPayload
    grant_type: OAuth2SessionGrantType
    client_id: UUID
    scope: str
    user_id: int | None
    organization_id: int | None
    include_refresh_token: bool

    def __post_init__(self) -> None:
        """Reject token material that does not match its persisted principal."""
        principal_type = session_principal_type(
            grant_type=self.grant_type,
            user_id=self.user_id,
            organization_id=self.organization_id,
        )
        if (
            self.access_payload.client_id != self.client_id
            or self.access_payload.scope != self.scope
        ):
            msg = "Access-token client and scope must match the OAuth2 session."
            raise ValueError(msg)
        if principal_type is PrincipalType.CLIENT:
            if (
                self.access_payload.principal_type is not PrincipalType.CLIENT
                or self.access_payload.subject != str(self.client_id)
                or self.access_payload.organization is not None
                or self.include_refresh_token
            ):
                msg = "Client-credentials token material has an invalid binding."
                raise ValueError(msg)
        elif self.access_payload.principal_type not in {None, PrincipalType.USER}:
            msg = "User token material has an invalid principal type."
            raise ValueError(msg)


@dataclass(frozen=True, slots=True)
class IssuedTokenSessionDTO:
    """Issued token material paired with its persisted session identifier."""

    tokens: IssuedTokens
    session_id: int
    session_public_id: UUID


class OAuth2TokenStateUpdateDTO(BaseModel):
    """Replacement values for a persisted OAuth2 token state."""

    model_config = ConfigDict(extra="forbid")

    access_expires_at: datetime
    access_jti: str
    access_token: str
    refresh_expires_at: datetime
    refresh_token: str


class OAuth2TokenStateReadDTO(BaseModel):
    """Current persisted token state used by services on read."""

    access_expires_at: datetime
    access_jti: str
    access_token_hash: str
    refresh_expires_at: datetime | None = None
    refresh_token_hash: str | None = None
    session_id: int
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)

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
    token_state: OAuth2TokenStateReadDTO
