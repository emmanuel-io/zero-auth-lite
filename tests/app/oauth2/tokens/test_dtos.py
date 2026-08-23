"""Tests for OAuth2 token persistence DTOs."""

from datetime import datetime, timedelta, UTC

import pytest
from app.oauth2.tokens.dtos import TokenPairReadDTO
from pydantic import ValidationError


pytestmark = pytest.mark.unit


@pytest.mark.parametrize("missing_field", ["created_at", "updated_at"])
def test_token_pair_read_requires_persisted_timestamps(missing_field: str) -> None:
    """Do not invent creation or update times for a stored token pair."""
    now = datetime.now(UTC)
    values = {
        "access_expires_at": now + timedelta(minutes=5),
        "access_jti": "access-jti",
        "access_token_hash": "access-hash",
        "session_id": 1,
        "created_at": now,
        "updated_at": now,
    }
    values.pop(missing_field)

    with pytest.raises(ValidationError):
        TokenPairReadDTO(**values)  # type: ignore[arg-type]
