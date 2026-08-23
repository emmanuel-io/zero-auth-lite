"""Tests for OAuth2 device-authorization persistence DTOs."""

from datetime import datetime, timedelta, UTC

import pytest
from app.oauth2.devices.dtos import DeviceAuthorizationReadDTO


pytestmark = pytest.mark.unit


@pytest.mark.parametrize("missing_field", ["created_at", "updated_at"])
def test_device_authorization_read_requires_persisted_timestamps(
    missing_field: str,
) -> None:
    """Do not invent creation or update times for stored device authorization."""
    now = datetime.now(UTC)
    values = {
        "id": 1,
        "device_code_hash": "device-hash",
        "user_code_hash": "user-hash",
        "client_id": "client",
        "scope": "",
        "expires_at": now + timedelta(minutes=5),
        "interval_seconds": 5,
        "organization_id": None,
        "created_at": now,
        "updated_at": now,
    }
    values.pop(missing_field)

    with pytest.raises(TypeError):
        DeviceAuthorizationReadDTO(**values)  # type: ignore[arg-type]
