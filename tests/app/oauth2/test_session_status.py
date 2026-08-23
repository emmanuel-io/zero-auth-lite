"""Tests for OAuth2 administration session status and HTTP schema naming."""

from datetime import datetime, timedelta, UTC

import pytest
from app.api.v1.organization.oauth2_sessions.schemas import OAuth2SessionResponse
from app.identity.public_ids import format_organization_id, format_user_id
from app.oauth2.organization_oauth2_session_dtos import OrganizationOAuth2SessionDTO
from app.oauth2.public_ids import format_oauth2_session_id
from app.oauth2.session_dtos import OAuth2SessionReadDTO
from app.oauth2.session_status import token_family_is_active
from app.oauth2.tokens.dtos import TokenPairReadDTO
from app.public_ids import PublicId


pytestmark = pytest.mark.unit


def test_oauth2_session_api_schema_hides_the_persistence_distinction() -> None:
    """Assert OAuth2 management calls its external identifier session_id."""
    properties = OAuth2SessionResponse.model_json_schema(mode="serialization")[
        "properties"
    ]

    assert "session_id" in properties
    assert "public_id" not in properties
    assert "session_ended_at" not in properties


def test_oauth2_session_http_schema_serializes_typed_public_ids() -> None:
    """Keep identifier prefixes and aliases at the versioned HTTP boundary."""
    now = datetime.now(UTC)
    dto = OrganizationOAuth2SessionDTO(
        public_id=PublicId(1),
        client_id="client",
        grant_type="authorization_code",
        scope="openid",
        user_public_id=PublicId(2),
        organization_public_id=PublicId(3),
        active=True,
        access_expires_at=now,
        refresh_expires_at=None,
        created_at=now,
        updated_at=now,
    )

    payload = OAuth2SessionResponse.model_validate(
        dto, from_attributes=True
    ).model_dump(mode="json", by_alias=True)

    assert payload["session_id"] == format_oauth2_session_id(PublicId(1))
    assert payload["user_id"] == format_user_id(PublicId(2))
    assert payload["organization_id"] == format_organization_id(PublicId(3))


@pytest.mark.parametrize(
    ("refresh_delta", "access_delta", "ended", "expected"),
    [
        (timedelta(minutes=1), timedelta(minutes=-1), False, True),
        (timedelta(minutes=-1), timedelta(minutes=1), False, False),
        (None, timedelta(minutes=1), False, True),
        (None, timedelta(minutes=-1), False, False),
        (timedelta(minutes=1), timedelta(minutes=1), True, False),
    ],
)
def test_token_family_activity_uses_effective_expiry_and_session_state(
    *,
    refresh_delta: timedelta | None,
    access_delta: timedelta,
    ended: bool,
    expected: bool,
) -> None:
    """Treat refresh expiry as authoritative when a refresh token exists."""
    now = datetime.now(UTC)
    token_pair = TokenPairReadDTO(
        access_expires_at=now + access_delta,
        access_jti="access-jti",
        access_token_hash="access-hash",  # noqa: S106
        refresh_expires_at=(now + refresh_delta if refresh_delta is not None else None),
        refresh_token_hash="refresh-hash" if refresh_delta is not None else None,
        session_id=1,
        created_at=now,
        updated_at=now,
    )
    oauth2_session = OAuth2SessionReadDTO(
        id=1,
        public_id=PublicId(1),
        client_id="client",
        grant_type="authorization_code",
        scope="openid",
        user_id=1,
        organization_id=1,
        created_at=now,
        updated_at=now,
        ended_at=now if ended else None,
    )

    assert token_family_is_active(token_pair, oauth2_session, now=now) is expected


@pytest.mark.parametrize("missing_field", ["created_at", "updated_at"])
def test_oauth2_session_read_requires_persisted_timestamps(missing_field: str) -> None:
    """Do not invent creation or update times for a stored OAuth2 session."""
    now = datetime.now(UTC)
    values = {
        "id": 1,
        "public_id": PublicId(1),
        "client_id": "client",
        "grant_type": "authorization_code",
        "scope": "openid",
        "user_id": 1,
        "organization_id": 1,
        "created_at": now,
        "updated_at": now,
    }
    values.pop(missing_field)

    with pytest.raises(TypeError):
        OAuth2SessionReadDTO(**values)  # type: ignore[arg-type]
