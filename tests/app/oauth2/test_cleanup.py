"""Tests for SQLAlchemy-owned OAuth2 cleanup."""

from datetime import datetime, timedelta, UTC

import pytest
from app.db.models.oauth2_authorization_code import (
    OAuth2AuthorizationCodeDB,
)
from app.oauth2.maintenance import run_oauth2_cleanup
from fastapi import FastAPI
from sqlalchemy import func, insert, select

from tests.fixtures.oauth2 import (
    create_oauth2_test_client,
    create_oauth2_test_identity,
)


pytestmark = pytest.mark.integration


@pytest.mark.asyncio
async def test_oauth2_cleanup_deletes_expired_authorization_codes(
    app: FastAPI,
) -> None:
    """Assert cleanup queries live and execute inside the adapter."""
    organization_id, user_id = await create_oauth2_test_identity(app)
    await create_oauth2_test_client(app)
    async with app.state.core_session_factory() as db_session:
        await db_session.execute(
            insert(OAuth2AuthorizationCodeDB).values(
                code_hash="a" * 64,
                client_id="client",
                redirect_uri="https://client.example/callback",
                scope="read",
                code_challenge="challenge",
                code_challenge_method="S256",
                expires_at=datetime.now(UTC) - timedelta(minutes=1),
                user_id=user_id,
                organization_id=organization_id,
            )
        )
        await db_session.commit()

        result = await run_oauth2_cleanup(db_session=db_session)

    assert result.authorization_codes == 1


@pytest.mark.asyncio
async def test_oauth2_cleanup_limits_each_table_batch(app: FastAPI) -> None:
    """Leave later expired rows for a subsequent short transaction."""
    organization_id, user_id = await create_oauth2_test_identity(app)
    await create_oauth2_test_client(app)
    async with app.state.core_session_factory() as db_session:
        await db_session.execute(
            insert(OAuth2AuthorizationCodeDB),
            [
                {
                    "code_hash": character * 64,
                    "client_id": "client",
                    "redirect_uri": "https://client.example/callback",
                    "scope": "read",
                    "code_challenge": "challenge",
                    "code_challenge_method": "S256",
                    "expires_at": datetime.now(UTC) - timedelta(minutes=1),
                    "user_id": user_id,
                    "organization_id": organization_id,
                }
                for character in ("a", "b")
            ],
        )
        await db_session.commit()

        result = await run_oauth2_cleanup(
            db_session=db_session,
            batch_size=1,
        )
        remaining = await db_session.scalar(
            select(func.count()).select_from(OAuth2AuthorizationCodeDB)
        )

    assert result.authorization_codes == 1
    assert remaining == 1
