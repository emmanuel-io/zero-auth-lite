"""Tests for OAuth2 token persistence DTOs."""

from datetime import datetime, timedelta, UTC
from typing import Any

import pytest
from app.oauth2.grants.types import OAuth2GrantType, OAuth2SessionGrantType
from app.oauth2.principal_types import PrincipalType, session_principal_type
from app.oauth2.tokens.access import (
    AccessTokenPayload,
    create_client_access_token_payload,
)
from app.oauth2.tokens.dtos import (
    NewTokenSessionDTO,
    OAuth2TokenStateReadDTO,
    OAuth2TokenStateUpdateDTO,
)
from pydantic import ValidationError

from tests.identifiers import deterministic_uuid


pytestmark = pytest.mark.unit


def test_token_state_update_rejects_unknown_fields() -> None:
    """Reject misspelled token persistence data instead of silently dropping it."""

    now = datetime.now(UTC)
    with pytest.raises(ValidationError, match="unexpected"):
        OAuth2TokenStateUpdateDTO.model_validate(
            {
                "access_expires_at": now + timedelta(minutes=5),
                "access_jti": "access-jti",
                "access_token": "access-token",
                "refresh_expires_at": now + timedelta(days=1),
                "refresh_token": "refresh-token",
                "unexpected": "value",
            }
        )


@pytest.mark.parametrize("missing_field", ["created_at", "updated_at"])
def test_token_state_read_requires_persisted_timestamps(missing_field: str) -> None:
    """Do not invent creation or update times for stored token state."""
    now = datetime.now(UTC)
    values: dict[str, Any] = {
        "access_expires_at": now + timedelta(minutes=5),
        "access_jti": "access-jti",
        "access_token_hash": "access-hash",
        "session_id": 1,
        "created_at": now,
        "updated_at": now,
    }
    values.pop(missing_field)

    with pytest.raises(ValidationError):
        OAuth2TokenStateReadDTO(**values)


@pytest.mark.parametrize(
    ("grant_type", "user_id", "organization_id", "expected"),
    [
        (OAuth2SessionGrantType.CLIENT_CREDENTIALS, None, None, PrincipalType.CLIENT),
        (OAuth2SessionGrantType.AUTHORIZATION_CODE, 1, 2, PrincipalType.USER),
        (OAuth2SessionGrantType.DEVICE_CODE, 1, 2, PrincipalType.USER),
    ],
)
def test_session_principal_type_accepts_supported_grant_bindings(
    grant_type: OAuth2SessionGrantType,
    user_id: int | None,
    organization_id: int | None,
    expected: PrincipalType,
) -> None:
    """Resolve each persisted grant to its required principal kind."""
    assert (
        session_principal_type(
            grant_type=grant_type,
            user_id=user_id,
            organization_id=organization_id,
        )
        is expected
    )


@pytest.mark.parametrize(
    ("grant_type", "user_id", "organization_id"),
    [
        (OAuth2SessionGrantType.CLIENT_CREDENTIALS, 1, 2),
        (OAuth2SessionGrantType.AUTHORIZATION_CODE, None, None),
        (OAuth2SessionGrantType.DEVICE_CODE, 1, None),
        (OAuth2GrantType.REFRESH_TOKEN, 1, 2),
    ],
)
def test_session_principal_type_rejects_invalid_grant_bindings(
    grant_type: OAuth2SessionGrantType | OAuth2GrantType,
    user_id: int | None,
    organization_id: int | None,
) -> None:
    """Fail closed for unsupported or incomplete persisted principals."""
    with pytest.raises(ValueError, match=r"principal binding|persisted OAuth2 grant"):
        session_principal_type(
            grant_type=grant_type,
            user_id=user_id,
            organization_id=organization_id,
        )


def test_new_token_session_rejects_grant_principal_mismatch() -> None:
    """Reject invalid session state before attempting its database insert."""
    with pytest.raises(ValueError, match="principal binding"):
        NewTokenSessionDTO(
            access_payload=create_client_access_token_payload(
                client_id=deterministic_uuid("client"),
                audience="audience",
            ),
            grant_type=OAuth2SessionGrantType.AUTHORIZATION_CODE,
            client_id=deterministic_uuid("client"),
            scope="",
            user_id=None,
            organization_id=None,
            include_refresh_token=False,
        )


def test_new_machine_session_rejects_user_token_claims() -> None:
    """Require machine token claims for client-credentials persistence."""
    with pytest.raises(ValueError, match="Client-credentials token material"):
        NewTokenSessionDTO(
            access_payload=AccessTokenPayload(
                subject="user",
                organization="org",
                audience="audience",
                access_jti="jti",
                client_id=deterministic_uuid("client"),
                principal_type=PrincipalType.USER,
            ),
            grant_type=OAuth2SessionGrantType.CLIENT_CREDENTIALS,
            client_id=deterministic_uuid("client"),
            scope="",
            user_id=None,
            organization_id=None,
            include_refresh_token=False,
        )
