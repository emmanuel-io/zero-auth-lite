"""Persistence data shapes for OAuth2 authorization state."""

from datetime import datetime
from typing import Annotated
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.core.time import as_utc_aware
from app.oauth2.specs import OAuth2Specs


class AuthorizationCodeCreateDTO(BaseModel):
    """Authorization code creation payload."""

    model_config = ConfigDict(extra="forbid")

    code_hash: str
    client_id: UUID
    redirect_uri: str
    scope: str = ""
    nonce: str | None = None
    code_challenge: str
    code_challenge_method: str
    expires_at: datetime
    authenticated_at: datetime
    user_id: int
    organization_id: int


class AuthorizationCodeReadDTO(AuthorizationCodeCreateDTO):
    """Authorization code read payload."""

    id: int
    used_at: datetime | None = None

    model_config = ConfigDict(from_attributes=True)

    @field_validator("expires_at", "authenticated_at", "used_at")
    @classmethod
    def normalize_database_datetimes(cls, value: datetime | None) -> datetime | None:
        """Normalize timestamps read from SQLite to aware UTC values."""
        return as_utc_aware(value) if value is not None else None


class AuthorizationTransactionCreateDTO(BaseModel):
    """Authorization request state persisted before browser consent."""

    model_config = ConfigDict(extra="forbid")

    transaction_hash: Annotated[str, Field(max_length=OAuth2Specs.HASH_LENGTH)]
    response_type: Annotated[
        str, Field(max_length=OAuth2Specs.RESPONSE_TYPE_LENGTH_MAX)
    ]
    client_id: UUID
    redirect_uri: Annotated[str, Field(max_length=OAuth2Specs.REDIRECT_URI_LENGTH_MAX)]
    scope: Annotated[str | None, Field(max_length=OAuth2Specs.SCOPE_LIST_LENGTH_MAX)]
    state: Annotated[str | None, Field(max_length=OAuth2Specs.STATE_LENGTH_MAX)]
    nonce: Annotated[str | None, Field(max_length=OAuth2Specs.NONCE_LENGTH_MAX)]
    code_challenge: Annotated[
        str, Field(max_length=OAuth2Specs.CODE_CHALLENGE_LENGTH_MAX)
    ]
    code_challenge_method: Annotated[
        str, Field(max_length=OAuth2Specs.CODE_CHALLENGE_METHOD_LENGTH_MAX)
    ]
    user_id: int | None = None
    organization_id: int | None = None
    expires_at: datetime


class AuthorizationTransactionReadDTO(AuthorizationTransactionCreateDTO):
    """Persisted authorization transaction."""

    id: int
    used_at: datetime | None = None

    model_config = ConfigDict(from_attributes=True)

    @field_validator("expires_at", "used_at")
    @classmethod
    def normalize_database_datetimes(cls, value: datetime | None) -> datetime | None:
        """Normalize timestamps read from SQLite to aware UTC values."""
        return as_utc_aware(value) if value is not None else None
