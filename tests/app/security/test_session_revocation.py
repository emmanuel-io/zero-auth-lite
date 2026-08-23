"""Integration tests for transactional security-session revocation."""

from datetime import datetime, timedelta, UTC

import pytest
from app.db.models.browser_session import BrowserSessionDB
from app.db.models.oauth2_session import OAuth2SessionDB
from app.db.models.oauth2_token_pair import OAuth2TokenPairDB
from app.db.models.organization_membership import OrganizationMembershipDB
from app.db.models.user import UserDB, UserEmailDB
from app.security.session_revocation import SecuritySessionRevocationService
from fastapi import FastAPI
from sqlalchemy import select

from tests.fixtures.auth import UserCredentials


pytestmark = pytest.mark.integration


async def seed_security_sessions(
    app: FastAPI,
    credentials: UserCredentials,
) -> tuple[int, int]:
    """Persist one browser session and token family for the fixture organization."""
    now = datetime.now(UTC)
    async with app.state.core_session_factory() as db_session:
        user = await db_session.scalar(
            select(UserDB)
            .join(UserEmailDB, UserEmailDB.user_id == UserDB.id)
            .where(UserEmailDB.normalized_email == credentials.email.lower())
        )
        assert user is not None
        membership = await db_session.get(OrganizationMembershipDB, user.id)
        assert membership is not None
        oauth2_session = OAuth2SessionDB(
            client_id="test-user-client",
            grant_type="authorization_code",
            scope="users:write",
            user_id=user.id,
            organization_id=membership.organization_id,
        )
        db_session.add_all(
            [
                BrowserSessionDB(
                    id="rollback-browser-session",
                    user_id=user.id,
                    csrf="rollback-csrf",
                    absolute_expires_at=now + timedelta(hours=8),
                    expires_at=now + timedelta(hours=1),
                    last_seen_at=now,
                ),
                oauth2_session,
            ]
        )
        await db_session.flush()
        db_session.add(
            OAuth2TokenPairDB(
                session_id=oauth2_session.id,
                access_token_hash="rollback-access-hash",  # noqa: S106
                access_jti="rollback-access-jti",
                refresh_token_hash="rollback-refresh-hash",  # noqa: S106
                access_expires_at=now + timedelta(minutes=15),
                refresh_expires_at=now + timedelta(days=1),
            )
        )
        await db_session.commit()
        return membership.organization_id, oauth2_session.id


@pytest.mark.asyncio
async def test_organization_security_revocation_rolls_back_as_one_transaction(
    app: FastAPI,
    verified_user_credentials: UserCredentials,
) -> None:
    """Restore every session type when the request transaction rolls back."""
    organization_id, oauth2_session_id = await seed_security_sessions(
        app,
        verified_user_credentials,
    )
    async with app.state.core_session_factory() as db_session:
        service = SecuritySessionRevocationService(db_session=db_session)
        await service.revoke_organization_security_sessions(
            organization_id=organization_id,
            reason="organization_sessions_revoked",
        )
        await db_session.rollback()

    async with app.state.core_session_factory() as db_session:
        user = await db_session.scalar(
            select(UserDB)
            .join(UserEmailDB, UserEmailDB.user_id == UserDB.id)
            .where(
                UserEmailDB.normalized_email == verified_user_credentials.email.lower()
            )
        )
        browser = await db_session.get(BrowserSessionDB, "rollback-browser-session")
        oauth2_session = await db_session.get(OAuth2SessionDB, oauth2_session_id)
        token_pair = await db_session.get(OAuth2TokenPairDB, oauth2_session_id)
        assert user is not None
        assert user.sessions_invalid_before is None
        assert browser is not None
        assert browser.revoked_at is None
        assert oauth2_session is not None
        assert oauth2_session.ended_at is None
        assert token_pair is not None
