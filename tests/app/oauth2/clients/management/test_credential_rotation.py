"""Tests for conditional OAuth2 client credential rotation."""

import pytest
from app.db.models.oauth2_client import OAuth2ClientDB
from app.oauth2.clients.management.credential_rotation import (
    OAuth2ClientCredentialRotationService,
)
from app.oauth2.clients.management.errors import OAuth2ClientConflictError
from app.security.principals import BrowserUserPrincipalContext
from app.security.roles import Role
from fastapi import FastAPI
from sqlalchemy import select, update

from app.oauth2.clients.management import credential_rotation
from tests.app.oauth2.clients.helpers import CONFIDENTIAL_ID, HASHER, seed_clients
from tests.identifiers import PublicId


pytestmark = pytest.mark.integration


@pytest.mark.asyncio
async def test_secret_rotation_preserves_a_concurrent_replacement(
    app: FastAPI,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Reject a stale rotation instead of overwriting the winning secret hash."""
    _, _, organization_id, _ = await seed_clients(app)
    concurrent_secret_hash = HASHER.hash("concurrent-client-secret")

    async def replace_secret_while_hashing(*_args: object) -> str:
        async with app.state.core_session_factory.begin() as concurrent_session:
            await concurrent_session.execute(
                update(OAuth2ClientDB)
                .where(OAuth2ClientDB.client_id == CONFIDENTIAL_ID)
                .values(client_secret=concurrent_secret_hash)
            )
        return HASHER.hash("losing-client-secret")

    monkeypatch.setattr(
        credential_rotation,
        "hash_password",
        replace_secret_while_hashing,
    )
    operator_ctx = BrowserUserPrincipalContext(
        user_id=1,
        organization_id=organization_id,
        raw_session_id="session",
        user_public_id=PublicId(1),
        organization_public_id=PublicId(1),
        roles=frozenset({Role.OPERATOR}),
    )
    async with app.state.core_session_factory() as db_session:
        service = OAuth2ClientCredentialRotationService(
            db_session=db_session,
            session_factory=app.state.core_session_factory,
            password_hasher=HASHER,
        )
        with pytest.raises(OAuth2ClientConflictError):
            await service.rotate_client_secret_autonomously(
                client_id=CONFIDENTIAL_ID,
                operator_ctx=operator_ctx,
            )

    async with app.state.core_session_factory() as db_session:
        stored_secret_hash = await db_session.scalar(
            select(OAuth2ClientDB.client_secret).where(
                OAuth2ClientDB.client_id == CONFIDENTIAL_ID
            )
        )
    assert stored_secret_hash == concurrent_secret_hash
