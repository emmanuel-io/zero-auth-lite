"""Black-box tests for OAuth2 client credential rotation."""

import base64
from datetime import datetime, timedelta, UTC
from uuid import UUID

import httpx
import pytest
from app.db.models.browser_session import BrowserSessionDB
from app.db.models.oauth2_client import OAuth2ClientDB
from app.password.pwdlib_hasher import PwdlibPasswordHasher
from fastapi import FastAPI, status
from sqlalchemy import select, update

from tests.fixtures.auth import UserCredentials
from tests.fixtures.oauth2 import (
    add_oauth2_required_context_route,
    authorization_code_from_redirect,
    CODE_VERIFIER,
    request_authorization_code,
)
from tests.routes.api.v1.server.oauth2_client_helpers import (
    create_public_client,
    operator_auth_headers,
    SERVER_CLIENTS_PATH,
)


pytestmark = pytest.mark.api
PASSWORD_HASHER = PwdlibPasswordHasher()


@pytest.mark.asyncio
async def test_confidential_client_secret_is_hashed_and_rotatable(
    app: FastAPI,
    client: httpx.AsyncClient,
    verified_user_credentials: UserCredentials,
) -> None:
    """Assert confidential client secrets are shown once and stored hashed."""
    headers = await operator_auth_headers(client, verified_user_credentials)
    create_response = await client.post(
        SERVER_CLIENTS_PATH,
        json={
            "name": "Server App",
            "grant_types": ["authorization_code"],
            "scopes": ["read"],
            "redirect_uris": ["https://server.example/callback"],
            "is_confidential": True,
            "is_active": True,
        },
        headers=headers,
    )
    assert create_response.status_code == status.HTTP_201_CREATED
    created = create_response.json()
    client_id = created["client_id"]
    raw_secret = created["client_secret"]
    assert raw_secret

    async with app.state.core_session_factory() as db_session:
        stored_secret = await db_session.scalar(
            select(OAuth2ClientDB.client_secret).where(
                OAuth2ClientDB.client_id == UUID(client_id)
            )
        )

    assert stored_secret is not None
    assert stored_secret != raw_secret
    assert PASSWORD_HASHER.verify(password=raw_secret, password_hash=stored_secret)

    rotate_response = await client.post(
        f"{SERVER_CLIENTS_PATH}/{client_id}/secrets", headers=headers
    )
    assert rotate_response.status_code == status.HTTP_200_OK
    assert rotate_response.json()["client_secret"] != raw_secret


@pytest.mark.asyncio
async def test_secret_rotation_discards_a_due_browser_session_slide(
    app: FastAPI,
    client: httpx.AsyncClient,
    verified_user_credentials: UserCredentials,
) -> None:
    """Discard incidental request writes before the autonomous rotation."""
    headers = await operator_auth_headers(client, verified_user_credentials)
    create_response = await client.post(
        SERVER_CLIENTS_PATH,
        json={
            "name": "Session Slide Client",
            "grant_types": ["client_credentials"],
            "scopes": ["read"],
            "redirect_uris": [],
            "is_confidential": True,
            "is_active": True,
        },
        headers=headers,
    )
    assert create_response.status_code == status.HTTP_201_CREATED

    stale_last_seen_at = datetime.now(UTC) - timedelta(
        seconds=app.state.settings.browser_session.slide_seconds + 1
    )
    async with app.state.core_session_factory.begin() as db_session:
        await db_session.execute(
            update(BrowserSessionDB).values(last_seen_at=stale_last_seen_at)
        )

    rotate_response = await client.post(
        f"{SERVER_CLIENTS_PATH}/{create_response.json()['client_id']}/secrets",
        headers=headers,
    )

    assert rotate_response.status_code == status.HTTP_200_OK
    async with app.state.core_session_factory() as db_session:
        last_seen_at = await db_session.scalar(select(BrowserSessionDB.last_seen_at))
    assert last_seen_at is not None
    assert last_seen_at.replace(tzinfo=UTC) == stale_last_seen_at


@pytest.mark.asyncio
@pytest.mark.system
async def test_secret_rotation_preserves_existing_tokens(
    app: FastAPI,
    client: httpx.AsyncClient,
    verified_user_credentials: UserCredentials,
) -> None:
    """Keep existing sessions valid while replacing future client authentication."""
    operator_headers = await operator_auth_headers(client, verified_user_credentials)
    redirect_uri = "https://rotation.example/callback"
    create_response = await client.post(
        SERVER_CLIENTS_PATH,
        json={
            "name": "Rotation Client",
            "grant_types": ["authorization_code", "refresh_token"],
            "scopes": ["read"],
            "redirect_uris": [redirect_uri],
            "is_confidential": True,
            "is_active": True,
        },
        headers=operator_headers,
    )
    assert create_response.status_code == status.HTTP_201_CREATED
    created = create_response.json()
    client_id = created["client_id"]
    old_secret = created["client_secret"]

    login_response = httpx.Response(
        status.HTTP_204_NO_CONTENT,
        headers=operator_headers,
    )
    authorize_response = await request_authorization_code(
        client,
        login_response=login_response,
        client_id=client_id,
        redirect_uri=redirect_uri,
    )
    old_basic = base64.b64encode(f"{client_id}:{old_secret}".encode()).decode()
    token_response = await client.post(
        "/oauth2/token",
        data={
            "grant_type": "authorization_code",
            "code": authorization_code_from_redirect(authorize_response),
            "redirect_uri": redirect_uri,
            "code_verifier": CODE_VERIFIER,
        },
        headers={"Authorization": f"Basic {old_basic}"},
    )
    assert token_response.status_code == status.HTTP_200_OK
    token_pair = token_response.json()

    rotate_response = await client.post(
        f"{SERVER_CLIENTS_PATH}/{client_id}/secrets",
        headers=operator_headers,
    )
    assert rotate_response.status_code == status.HTTP_200_OK
    new_secret = rotate_response.json()["client_secret"]
    new_basic = base64.b64encode(f"{client_id}:{new_secret}".encode()).decode()

    add_oauth2_required_context_route(app)
    bearer_response = await client.get(
        "/test/oauth2/required-context",
        headers={"Authorization": f"Bearer {token_pair['access_token']}"},
    )
    old_secret_response = await client.post(
        "/oauth2/token",
        data={
            "grant_type": "refresh_token",
            "refresh_token": token_pair["refresh_token"],
        },
        headers={"Authorization": f"Basic {old_basic}"},
    )
    refresh_response = await client.post(
        "/oauth2/token",
        data={
            "grant_type": "refresh_token",
            "refresh_token": token_pair["refresh_token"],
        },
        headers={"Authorization": f"Basic {new_basic}"},
    )

    assert bearer_response.status_code == status.HTTP_200_OK
    assert old_secret_response.status_code == status.HTTP_401_UNAUTHORIZED
    assert old_secret_response.json()["error"] == "invalid_client"
    assert refresh_response.status_code == status.HTTP_200_OK


@pytest.mark.asyncio
async def test_rotate_secret_for_missing_or_public_client_returns_errors(
    client: httpx.AsyncClient,
    verified_user_credentials: UserCredentials,
) -> None:
    """Assert rotation only applies to existing confidential clients."""
    headers = await operator_auth_headers(client, verified_user_credentials)
    create_response = await create_public_client(client, headers)
    assert create_response.status_code == status.HTTP_201_CREATED

    missing_response = await client.post(
        f"{SERVER_CLIENTS_PATH}/00000000-0000-4000-8000-000000000000/secrets",
        headers=headers,
    )
    public_response = await client.post(
        f"{SERVER_CLIENTS_PATH}/{create_response.json()['client_id']}/secrets",
        headers=headers,
    )
    assert missing_response.status_code == status.HTTP_404_NOT_FOUND
    assert missing_response.json()["code"] == "OAUTH2_CLIENT_NOT_FOUND"
    assert public_response.status_code == status.HTTP_400_BAD_REQUEST
    assert public_response.json()["code"] == "INVALID_OAUTH2_CLIENT"
