"""Authentication-token persistence data shapes."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING


if TYPE_CHECKING:
    from datetime import datetime

    from app.auth_tokens.enums import AuthTokenPurpose


@dataclass(frozen=True, slots=True)
class AuthTokenCreateDTO:
    """Authentication-token creation data."""

    user_email_id: int
    purpose: AuthTokenPurpose
    token_hash: str
    expires_at: datetime
    source_event_id: str | None = field(default=None, kw_only=True)
    source_event_occurred_at: datetime | None = field(default=None, kw_only=True)
    derivation_key_id: str | None = field(default=None, kw_only=True)


@dataclass(frozen=True, slots=True)
class AuthTokenReadDTO(AuthTokenCreateDTO):
    """Stored authentication token."""

    id: int
    used_at: datetime | None = None
