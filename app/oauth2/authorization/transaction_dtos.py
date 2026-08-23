"""Server-side OAuth2 authorization-transaction data shapes."""

from datetime import datetime
from typing import Annotated

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.core.time import as_utc_aware
from app.oauth2.specs import OAuth2Specs


class AuthorizationTransactionCreateDTO(BaseModel):
    """Authorization request state persisted before browser consent."""

    transaction_hash: Annotated[str, Field(max_length=OAuth2Specs.HASH_LENGTH)]
    response_type: Annotated[
        str, Field(max_length=OAuth2Specs.RESPONSE_TYPE_LENGTH_MAX)
    ]
    client_id: Annotated[str, Field(max_length=OAuth2Specs.CLIENT_ID_LENGTH_MAX)]
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
