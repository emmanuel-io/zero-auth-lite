"""ORM-to-DTO mapping for OAuth2 device authorizations."""

from datetime import datetime

from app.core.time import as_utc_aware
from app.db.models.oauth2_device_authorization import OAuth2DeviceAuthorizationDB
from app.oauth2.devices.dtos import DeviceAuthorizationReadDTO


def _optional_utc(value: datetime | None) -> datetime | None:
    """Normalize an optional database datetime to aware UTC."""
    return as_utc_aware(value) if value is not None else None


def to_device_authorization_dto(
    device: OAuth2DeviceAuthorizationDB,
) -> DeviceAuthorizationReadDTO:
    """Convert a device-authorization row to its stable DTO."""
    return DeviceAuthorizationReadDTO(
        id=device.id,
        device_code_hash=device.device_code_hash,
        user_code_hash=device.user_code_hash,
        client_id=device.client_id,
        scope=device.scope,
        expires_at=as_utc_aware(device.expires_at),
        interval_seconds=device.interval_seconds,
        organization_id=device.organization_id,
        last_polled_at=_optional_utc(device.last_polled_at),
        approved_at=_optional_utc(device.approved_at),
        denied_at=_optional_utc(device.denied_at),
        used_at=_optional_utc(device.used_at),
        user_id=device.user_id,
        created_at=as_utc_aware(device.created_at),
        updated_at=as_utc_aware(device.updated_at),
    )
