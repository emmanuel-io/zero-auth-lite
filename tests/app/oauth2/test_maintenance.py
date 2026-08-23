"""Tests for cleanup of terminal OAuth2 persistence records."""

import base64
from datetime import datetime, timedelta, UTC

import httpx
import pytest
from app.db.models.oauth2_authorization_code import (
    OAuth2AuthorizationCodeDB,
)
from app.db.models.oauth2_authorization_transaction import (
    OAuth2AuthorizationTransactionDB,
)
from app.db.models.oauth2_device_authorization import (
    OAuth2DeviceAuthorizationDB,
)
from app.db.models.oauth2_session import OAuth2SessionDB
from app.db.models.oauth2_token_pair import OAuth2TokenPairDB
from app.oauth2.maintenance import run_oauth2_cleanup
from fastapi import FastAPI, status
from sqlalchemy import func, select, update

from tests.fixtures.oauth2 import (
    create_confidential_machine_client,
    create_oauth2_test_identity,
)


pytestmark = pytest.mark.integration


@pytest.mark.asyncio
async def test_oauth2_cleanup_removes_expired_terminal_storage(
    app: FastAPI,
    client: httpx.AsyncClient,
) -> None:
    """Assert OAuth2 cleanup removes expired and terminal storage rows."""
    organization_id, user_id = await create_oauth2_test_identity(app)
    raw_secret = await create_confidential_machine_client(app)
    basic_payload = base64.b64encode(f"machine-client:{raw_secret}".encode()).decode()
    token_response = await client.post(
        "/oauth2/token",
        data={
            "grant_type": "client_credentials",
            "scope": "service:read",
        },
        headers={"Authorization": f"Basic {basic_payload}"},
    )
    assert token_response.status_code == status.HTTP_200_OK
    cutoff = datetime.now(UTC)
    async with app.state.core_session_factory() as db_session:
        db_session.add(
            OAuth2AuthorizationCodeDB(
                code_hash="expired-code-hash",
                client_id="machine-client",
                redirect_uri="https://client.example/callback",
                scope="service:read",
                code_challenge="challenge",
                code_challenge_method="S256",
                expires_at=cutoff - timedelta(seconds=1),
                user_id=user_id,
                organization_id=organization_id,
            )
        )
        db_session.add(
            OAuth2DeviceAuthorizationDB(
                device_code_hash="expired-device-code-hash",
                user_code_hash="expired-user-code-hash",
                client_id="machine-client",
                scope="service:read",
                expires_at=cutoff - timedelta(seconds=1),
                interval_seconds=5,
            )
        )
        db_session.add(
            OAuth2AuthorizationTransactionDB(
                transaction_hash="expired-transaction-hash",
                response_type="code",
                client_id="machine-client",
                redirect_uri="https://client.example/callback",
                scope="service:read",
                code_challenge="challenge",
                code_challenge_method="S256",
                expires_at=cutoff - timedelta(seconds=1),
                user_id=user_id,
                organization_id=organization_id,
            )
        )
        await db_session.execute(
            update(OAuth2TokenPairDB).values(
                access_expires_at=cutoff - timedelta(seconds=1)
            )
        )
        await db_session.commit()

        result = await run_oauth2_cleanup(
            db_session=db_session,
            now=cutoff,
        )

        remaining_codes = await db_session.scalar(
            select(func.count()).select_from(OAuth2AuthorizationCodeDB)
        )
        remaining_devices = await db_session.scalar(
            select(func.count()).select_from(OAuth2DeviceAuthorizationDB)
        )
        remaining_transactions = await db_session.scalar(
            select(func.count()).select_from(OAuth2AuthorizationTransactionDB)
        )
        remaining_tokens = await db_session.scalar(
            select(func.count()).select_from(OAuth2TokenPairDB)
        )
        remaining_sessions = await db_session.scalar(
            select(func.count()).select_from(OAuth2SessionDB)
        )

    assert result.authorization_codes == 1
    assert result.authorization_transactions == 1
    assert result.device_authorizations == 1
    assert result.token_pairs == 1
    assert result.sessions == 1
    assert remaining_codes == 0
    assert remaining_transactions == 0
    assert remaining_devices == 0
    assert remaining_tokens == 0
    assert remaining_sessions == 0


@pytest.mark.asyncio
async def test_oauth2_cleanup_removes_orphaned_sessions(
    app: FastAPI,
) -> None:
    """Remove an OAuth2 session that no longer has a SQL token pair."""
    await create_confidential_machine_client(app)
    _organization_id, _user_id = await create_oauth2_test_identity(app)
    async with app.state.core_session_factory() as db_session:
        session = OAuth2SessionDB(
            client_id="machine-client",
            grant_type="client_credentials",
            scope="service:read",
            user_id=None,
            organization_id=None,
        )
        db_session.add(session)
        await db_session.commit()
        session_id = session.id

        result = await run_oauth2_cleanup(db_session=db_session)
        remaining_session = await db_session.get(OAuth2SessionDB, session_id)

    assert result.token_pairs == 0
    assert result.sessions == 1
    assert remaining_session is None
