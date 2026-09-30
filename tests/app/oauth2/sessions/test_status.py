"""Tests for OAuth2 session and token-family status calculations."""

from datetime import datetime, timedelta, UTC

import pytest
from app.oauth2.grants.types import OAuth2SessionGrantType
from app.oauth2.sessions.dtos import OAuth2SessionReadDTO
from app.oauth2.sessions.status import token_family_is_current
from app.oauth2.tokens.dtos import OAuth2TokenStateReadDTO

from tests.identifiers import deterministic_uuid, PublicId


pytestmark = pytest.mark.unit


@pytest.mark.parametrize(
    ("refresh_delta", "access_delta", "ended", "expected"),
    [
        (timedelta(minutes=1), timedelta(minutes=-1), False, True),
        (timedelta(minutes=-1), timedelta(minutes=1), False, False),
        (None, timedelta(minutes=1), False, True),
        (None, timedelta(minutes=-1), False, False),
        (timedelta(0), timedelta(minutes=1), False, False),
        (None, timedelta(0), False, False),
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
    token_state = OAuth2TokenStateReadDTO(
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
        client_id=deterministic_uuid("client"),
        grant_type=OAuth2SessionGrantType.AUTHORIZATION_CODE,
        scope="openid",
        user_id=1,
        organization_id=1,
        created_at=now,
        updated_at=now,
        ended_at=now if ended else None,
    )

    assert token_family_is_current(token_state, oauth2_session, now=now) is expected
