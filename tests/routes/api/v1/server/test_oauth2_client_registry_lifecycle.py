"""Black-box lifecycle tests for the operator OAuth2 client registry."""

import httpx
import pytest
from app.db.models.oauth2_session import OAuth2SessionDB
from app.db.models.oauth2_token_state import OAuth2TokenStateDB
from fastapi import FastAPI, status
from sqlalchemy import select

from tests.fixtures.auth import issue_user_token, UserCredentials
from tests.fixtures.routes import BrowserClientFactory
from tests.identifiers import (
    deterministic_uuid,
    parse_public_id as parse_client_id,
    UUID4_VERSION,
)
from tests.routes.api.v1.server.oauth2_client_helpers import (
    create_public_client,
    DEFAULT_CLIENT_LIST_LIMIT,
    operator_auth_headers,
    SERVER_CLIENTS_PATH,
)


pytestmark = pytest.mark.api


@pytest.mark.asyncio
@pytest.mark.system
async def test_operator_can_create_list_read_replace_and_delete_oauth2_client(
    client: httpx.AsyncClient,
    verified_user_credentials: UserCredentials,
) -> None:
    """Assert operator client CRUD endpoints manage global OAuth2 clients."""
    headers = await operator_auth_headers(client, verified_user_credentials)

    create_response = await create_public_client(client, headers)
    assert create_response.status_code == status.HTTP_201_CREATED
    created = create_response.json()
    client_id = created["client_id"]
    assert parse_client_id(client_id).version == UUID4_VERSION
    assert created["client_secret"] is None
    assert created["requires_consent"] is True
    assert created["is_active"] is True

    list_response = await client.get(SERVER_CLIENTS_PATH, headers=headers)
    read_response = await client.get(
        f"{SERVER_CLIENTS_PATH}/{client_id}", headers=headers
    )
    replacement_response = await client.put(
        f"{SERVER_CLIENTS_PATH}/{client_id}",
        json={
            "name": "Updated UI",
            "grant_types": ["authorization_code"],
            "scopes": ["read", "write"],
            "redirect_uris": ["https://client.example/updated"],
            "is_confidential": False,
            "requires_consent": True,
            "is_active": False,
        },
        headers=headers,
    )
    delete_response = await client.delete(
        f"{SERVER_CLIENTS_PATH}/{client_id}",
        headers=headers,
    )
    missing_response = await client.get(
        f"{SERVER_CLIENTS_PATH}/{client_id}", headers=headers
    )

    assert list_response.status_code == status.HTTP_200_OK
    assert client_id in [item["client_id"] for item in list_response.json()["items"]]
    assert list_response.json()["limit"] == DEFAULT_CLIENT_LIST_LIMIT
    assert list_response.json()["total"] >= 1
    assert read_response.status_code == status.HTTP_200_OK
    assert read_response.json()["client_id"] == client_id
    assert read_response.json()["is_active"] is True
    assert replacement_response.status_code == status.HTTP_200_OK
    assert replacement_response.json()["name"] == "Updated UI"
    assert replacement_response.json()["requires_consent"] is True
    assert replacement_response.json()["is_active"] is False
    assert delete_response.status_code == status.HTTP_204_NO_CONTENT
    assert delete_response.content == b""
    assert missing_response.status_code == status.HTTP_404_NOT_FOUND


@pytest.mark.asyncio
@pytest.mark.system
async def test_narrowing_client_scopes_revokes_existing_token_families(
    app: FastAPI,
    client: httpx.AsyncClient,
    browser_client_factory: BrowserClientFactory,
    verified_user_credentials: UserCredentials,
) -> None:
    """Make an administrative capability reduction effective at commit."""
    token_response = await issue_user_token(
        app,
        client,
        verified_user_credentials,
        scope="read",
    )
    assert token_response.status_code == status.HTTP_200_OK
    async with app.state.core_session_factory() as db_session:
        token_state = await db_session.scalar(
            select(OAuth2TokenStateDB)
            .join(OAuth2SessionDB, OAuth2SessionDB.id == OAuth2TokenStateDB.session_id)
            .where(OAuth2SessionDB.client_id == deterministic_uuid("test-user-client"))
        )
        assert token_state is not None
        oauth2_session_id = token_state.session_id

    async with browser_client_factory() as operator_client:
        headers = await operator_auth_headers(
            operator_client, verified_user_credentials
        )
        response = await operator_client.put(
            f"{SERVER_CLIENTS_PATH}/{deterministic_uuid('test-user-client')}",
            json={
                "name": "Test User Client",
                "grant_types": ["authorization_code", "refresh_token"],
                "scopes": [],
                "redirect_uris": ["https://test-client.example/callback"],
                "is_confidential": False,
                "requires_consent": True,
                "is_active": True,
            },
            headers=headers,
        )

    assert response.status_code == status.HTTP_200_OK
    async with app.state.core_session_factory() as db_session:
        assert await db_session.get(OAuth2TokenStateDB, oauth2_session_id) is None
        oauth2_session = await db_session.get(OAuth2SessionDB, oauth2_session_id)
        assert oauth2_session is not None
        assert oauth2_session.ended_at is not None


@pytest.mark.asyncio
async def test_operator_can_create_disabled_client_and_reenable_it(
    client: httpx.AsyncClient,
    verified_user_credentials: UserCredentials,
) -> None:
    """Assert operators can create disabled clients and later re-enable them."""
    headers = await operator_auth_headers(client, verified_user_credentials)

    create_response = await client.post(
        SERVER_CLIENTS_PATH,
        json={
            "name": "Disabled Operator UI",
            "grant_types": ["authorization_code"],
            "scopes": ["read"],
            "redirect_uris": ["https://client.example/callback"],
            "is_confidential": False,
            "requires_consent": True,
            "is_active": False,
        },
        headers=headers,
    )

    assert create_response.status_code == status.HTTP_201_CREATED
    client_id = create_response.json()["client_id"]
    assert create_response.json()["is_active"] is False

    read_response = await client.get(
        f"{SERVER_CLIENTS_PATH}/{client_id}",
        headers=headers,
    )
    assert read_response.status_code == status.HTTP_200_OK
    assert read_response.json()["is_active"] is False

    replacement_response = await client.put(
        f"{SERVER_CLIENTS_PATH}/{client_id}",
        json={
            "name": "Enabled Operator UI",
            "grant_types": ["authorization_code"],
            "scopes": ["read"],
            "redirect_uris": ["https://client.example/callback"],
            "is_confidential": False,
            "requires_consent": True,
            "is_active": True,
        },
        headers=headers,
    )

    assert replacement_response.status_code == status.HTTP_200_OK
    assert replacement_response.json()["is_active"] is True

    list_response = await client.get(SERVER_CLIENTS_PATH, headers=headers)
    assert list_response.status_code == status.HTTP_200_OK
    listed = {
        item["client_id"]: item["is_active"] for item in list_response.json()["items"]
    }
    assert listed[client_id] is True
