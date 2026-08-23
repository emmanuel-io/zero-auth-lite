"""Tests for shared OAuth2 token issuance and persistence."""

from datetime import datetime, timedelta, UTC

import pytest
from app.db.models.oauth2_client import OAuth2ClientDB
from app.db.models.oauth2_session import OAuth2SessionDB
from app.db.models.oauth2_token_pair import OAuth2TokenPairDB
from app.oauth2.oidc.keys import get_signing_key
from app.oauth2.settings import OAuth2GrantType
from app.oauth2.tokens.access import create_client_access_token_payload
from app.oauth2.tokens.dtos import NewTokenSessionDTO
from app.oauth2.tokens.hash import hash_oauth2_token
from app.oauth2.tokens.issuance import TokenIssuanceService
from fastapi import FastAPI
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession


pytestmark = pytest.mark.integration


@pytest.mark.asyncio
async def test_issuance_persists_one_hashed_machine_token_session(
    app: FastAPI, db_session: AsyncSession
) -> None:
    """Persist new-session authority without storing bearer material."""
    settings = app.state.settings.oauth2
    service = TokenIssuanceService(
        db_session=db_session,
        settings=settings,
        signing_key=get_signing_key(settings.prv_key_b64),
    )
    db_session.add(
        OAuth2ClientDB(
            client_id="machine-client",
            client_secret="hashed-secret",  # noqa: S106
            name="Machine Client",
            grant_types=[OAuth2GrantType.client_credentials],
            scopes=["read"],
            redirect_uris=[],
            is_confidential=True,
            requires_consent=False,
            is_active=True,
        )
    )
    await db_session.flush()

    issued = await service.issue_new_session(
        NewTokenSessionDTO(
            access_payload=create_client_access_token_payload(
                client_id="machine-client",
                audience=settings.jwt_audience,
                scope="read",
            ),
            grant_type=OAuth2GrantType.client_credentials,
            client_id="machine-client",
            scope="read",
            user_id=None,
            organization_id=None,
            include_refresh_token=False,
        )
    )

    session = await db_session.get(OAuth2SessionDB, issued.session_id)
    stored_pair = await db_session.scalar(
        select(OAuth2TokenPairDB).where(
            OAuth2TokenPairDB.session_id == issued.session_id
        )
    )
    response = service.build_response(issued.token_pair)
    secret = settings.token_hash_secret.get_secret_value()

    assert session is not None
    assert session.user_id is None
    assert session.client_id == "machine-client"
    assert session.grant_type == OAuth2GrantType.client_credentials
    assert session.scope == "read"
    assert session.organization_id is None
    assert stored_pair is not None
    assert stored_pair.access_token_hash == hash_oauth2_token(
        token=issued.token_pair.access_token,
        secret=secret,
    )
    assert stored_pair.refresh_token_hash is None
    assert response.access_token == issued.token_pair.access_token
    assert response.refresh_token is None


@pytest.mark.asyncio
async def test_rotation_creation_preserves_the_existing_family_deadline(
    app: FastAPI, db_session: AsyncSession
) -> None:
    """Create replacement material without extending refresh-family lifetime."""
    settings = app.state.settings.oauth2
    service = TokenIssuanceService(
        db_session=db_session,
        settings=settings,
        signing_key=get_signing_key(settings.prv_key_b64),
    )
    deadline = datetime.now(UTC) + timedelta(minutes=5)

    token_pair = service.create_rotation_tokens(
        access_payload=create_client_access_token_payload(
            client_id="machine-client",
            audience=settings.jwt_audience,
        ),
        refresh_deadline=deadline,
    )

    assert token_pair.refresh_token is not None
    assert token_pair.refresh_expires_at == deadline
