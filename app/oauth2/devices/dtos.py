"""OAuth2 device-authorization persistence data shapes."""

from dataclasses import dataclass
from datetime import datetime


@dataclass(frozen=True, slots=True)
class DeviceAuthorizationCreateDTO:
    """Device authorization creation data."""

    device_code_hash: str
    user_code_hash: str
    client_id: str
    scope: str
    expires_at: datetime
    interval_seconds: int
    organization_id: int | None


@dataclass(frozen=True, slots=True)
class DeviceAuthorizationReadDTO(DeviceAuthorizationCreateDTO):
    """Stored device authorization state."""

    id: int
    created_at: datetime
    updated_at: datetime
    last_polled_at: datetime | None = None
    approved_at: datetime | None = None
    denied_at: datetime | None = None
    used_at: datetime | None = None
    user_id: int | None = None
