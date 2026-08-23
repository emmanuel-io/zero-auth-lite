"""Black-box tests for OAuth2 client credential rotation."""

import httpx
import pytest
from app.db.models.oauth2_client import OAuth2ClientDB
from app.password.pwdlib_hasher import PwdlibPasswordHasher
from fastapi import FastAPI, status
from sqlalchemy import select

from tests.fixtures.auth import UserCredentials
from tests.routes.api.v1.admin.oauth2_client_helpers import (
    admin_auth_headers,
    ADMIN_CLIENTS_PATH,
    create_public_client,
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
    headers = await admin_auth_headers(client, verified_user_credentials)
    create_response = await client.post(
        ADMIN_CLIENTS_PATH,
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
                OAuth2ClientDB.client_id == client_id
            )
        )

    assert stored_secret is not None
    assert stored_secret != raw_secret
    assert PASSWORD_HASHER.verify(password=raw_secret, password_hash=stored_secret)

    rotate_response = await client.post(
        f"{ADMIN_CLIENTS_PATH}/{client_id}/secrets", headers=headers
    )
    assert rotate_response.status_code == status.HTTP_200_OK
    assert rotate_response.json()["client_secret"] != raw_secret


@pytest.mark.asyncio
async def test_rotate_secret_for_missing_or_public_client_returns_errors(
    client: httpx.AsyncClient,
    verified_user_credentials: UserCredentials,
) -> None:
    """Assert rotation only applies to existing confidential clients."""
    headers = await admin_auth_headers(client, verified_user_credentials)
    create_response = await create_public_client(client, headers)
    assert create_response.status_code == status.HTTP_201_CREATED

    missing_response = await client.post(
        f"{ADMIN_CLIENTS_PATH}/missing-client/secrets", headers=headers
    )
    public_response = await client.post(
        f"{ADMIN_CLIENTS_PATH}/{create_response.json()['client_id']}/secrets",
        headers=headers,
    )
    assert missing_response.status_code == status.HTTP_404_NOT_FOUND
    assert missing_response.json()["code"] == "OAUTH2_CLIENT_NOT_FOUND"
    assert public_response.status_code == status.HTTP_400_BAD_REQUEST
    assert public_response.json()["code"] == "INVALID_OAUTH2_CLIENT"
