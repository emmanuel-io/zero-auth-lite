"""OAuth2 authorization-code persistence data shapes."""

from datetime import datetime

from pydantic import BaseModel, ConfigDict, field_validator

from app.core.time import as_utc_aware


class AuthorizationCodeCreateDTO(BaseModel):
    """Authorization code creation payload."""

    code_hash: str
    client_id: str
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
    """Pydantic model configuration."""

    @field_validator("expires_at", "authenticated_at", "used_at")
    @classmethod
    def normalize_database_datetimes(cls, value: datetime | None) -> datetime | None:
        """Normalize timestamps read from SQLite to aware UTC values."""
        return as_utc_aware(value) if value is not None else None
