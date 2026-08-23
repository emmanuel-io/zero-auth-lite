"""Black-box tests for the operator OAuth2 client registry."""

import httpx
import pytest
from app.db.models.oauth2_session import OAuth2SessionDB
from app.db.models.oauth2_token_pair import OAuth2TokenPairDB
from fastapi import FastAPI, status
from sqlalchemy import select

from tests.fixtures.auth import issue_user_token, UserCredentials
from tests.fixtures.routes import BrowserClientFactory
from tests.fixtures.settings import app_settings
from tests.routes.api.v1.admin.oauth2_client_helpers import (
    admin_auth_headers,
    ADMIN_CLIENTS_PATH,
    create_public_client,
    DEFAULT_CLIENT_LIST_LIMIT,
)


pytestmark = pytest.mark.api


@pytest.mark.asyncio
@pytest.mark.system
async def test_admin_can_create_list_read_replace_and_delete_oauth2_client(
    client: httpx.AsyncClient,
    verified_user_credentials: UserCredentials,
) -> None:
    """Assert operator client CRUD endpoints manage global OAuth2 clients."""
    headers = await admin_auth_headers(client, verified_user_credentials)

    create_response = await create_public_client(client, headers)
    assert create_response.status_code == status.HTTP_201_CREATED
    created = create_response.json()
    client_id = created["client_id"]
    assert client_id.startswith("oa_")
    assert created["client_secret"] is None
    assert created["requires_consent"] is True
    assert created["is_active"] is True

    list_response = await client.get(ADMIN_CLIENTS_PATH, headers=headers)
    read_response = await client.get(
        f"{ADMIN_CLIENTS_PATH}/{client_id}", headers=headers
    )
    replacement_response = await client.put(
        f"{ADMIN_CLIENTS_PATH}/{client_id}",
        json={
            "name": "Updated UI",
            "grant_types": ["authorization_code"],
            "scopes": ["read", "write"],
            "redirect_uris": ["https://client.example/updated"],
            "is_confidential": False,
            "requires_consent": True,
            "is_active": False,
            "user_organization_access": "unrestricted",
        },
        headers=headers,
    )
    delete_response = await client.delete(
        f"{ADMIN_CLIENTS_PATH}/{client_id}",
        headers=headers,
    )
    missing_response = await client.get(
        f"{ADMIN_CLIENTS_PATH}/{client_id}", headers=headers
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
        token_pair = await db_session.scalar(
            select(OAuth2TokenPairDB)
            .join(OAuth2SessionDB, OAuth2SessionDB.id == OAuth2TokenPairDB.session_id)
            .where(OAuth2SessionDB.client_id == "test-user-client")
        )
        assert token_pair is not None
        oauth2_session_id = token_pair.session_id

    async with browser_client_factory() as admin_client:
        headers = await admin_auth_headers(admin_client, verified_user_credentials)
        response = await admin_client.put(
            f"{ADMIN_CLIENTS_PATH}/test-user-client",
            json={
                "name": "Test User Client",
                "grant_types": ["authorization_code", "refresh_token"],
                "scopes": [],
                "redirect_uris": ["https://test-client.example/callback"],
                "is_confidential": False,
                "requires_consent": True,
                "is_active": True,
                "user_organization_access": "unrestricted",
            },
            headers=headers,
        )

    assert response.status_code == status.HTTP_200_OK
    async with app.state.core_session_factory() as db_session:
        assert await db_session.get(OAuth2TokenPairDB, oauth2_session_id) is None
        oauth2_session = await db_session.get(OAuth2SessionDB, oauth2_session_id)
        assert oauth2_session is not None
        assert oauth2_session.ended_at is not None


@pytest.mark.asyncio
async def test_admin_can_create_disabled_client_and_reenable_it(
    client: httpx.AsyncClient,
    verified_user_credentials: UserCredentials,
) -> None:
    """Assert operators can create disabled clients and later re-enable them."""
    headers = await admin_auth_headers(client, verified_user_credentials)

    create_response = await client.post(
        ADMIN_CLIENTS_PATH,
        json={
            "name": "Disabled Admin UI",
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
        f"{ADMIN_CLIENTS_PATH}/{client_id}",
        headers=headers,
    )
    assert read_response.status_code == status.HTTP_200_OK
    assert read_response.json()["is_active"] is False

    replacement_response = await client.put(
        f"{ADMIN_CLIENTS_PATH}/{client_id}",
        json={
            "name": "Enabled Admin UI",
            "grant_types": ["authorization_code"],
            "scopes": ["read"],
            "redirect_uris": ["https://client.example/callback"],
            "is_confidential": False,
            "requires_consent": True,
            "is_active": True,
            "user_organization_access": "unrestricted",
        },
        headers=headers,
    )

    assert replacement_response.status_code == status.HTTP_200_OK
    assert replacement_response.json()["is_active"] is True

    list_response = await client.get(ADMIN_CLIENTS_PATH, headers=headers)
    assert list_response.status_code == status.HTTP_200_OK
    listed = {
        item["client_id"]: item["is_active"] for item in list_response.json()["items"]
    }
    assert listed[client_id] is True


@pytest.mark.asyncio
@pytest.mark.negative
async def test_general_client_replacement_rejects_machine_organization_policy(
    client: httpx.AsyncClient,
    verified_user_credentials: UserCredentials,
) -> None:
    """Keep machine mode and assignments on their atomic dedicated endpoint."""
    headers = await admin_auth_headers(client, verified_user_credentials)
    create_response = await create_public_client(client, headers)
    assert create_response.status_code == status.HTTP_201_CREATED

    response = await client.put(
        f"{ADMIN_CLIENTS_PATH}/{create_response.json()['client_id']}",
        json={
            "name": "Unexpected Machine Update",
            "grant_types": ["authorization_code"],
            "scopes": ["read"],
            "redirect_uris": ["https://client.example/callback"],
            "is_confidential": False,
            "requires_consent": True,
            "is_active": True,
            "user_organization_access": "unrestricted",
            "machine_organization_access": "unrestricted",
        },
        headers=headers,
    )

    assert response.status_code == status.HTTP_422_UNPROCESSABLE_CONTENT


@pytest.mark.asyncio
@pytest.mark.negative
async def test_client_creation_rejects_machine_organization_policy(
    client: httpx.AsyncClient,
    verified_user_credentials: UserCredentials,
) -> None:
    """Require machine mode and assignments to be configured after creation."""
    headers = await admin_auth_headers(client, verified_user_credentials)

    response = await client.post(
        ADMIN_CLIENTS_PATH,
        json={
            "name": "Unexpected Machine Client",
            "grant_types": ["client_credentials"],
            "scopes": ["service:read"],
            "redirect_uris": [],
            "is_confidential": True,
            "requires_consent": True,
            "is_active": True,
            "machine_organization_access": "unrestricted",
        },
        headers=headers,
    )

    assert response.status_code == status.HTTP_422_UNPROCESSABLE_CONTENT


@pytest.mark.asyncio
@pytest.mark.negative
async def test_public_authorization_client_cannot_disable_consent(
    client: httpx.AsyncClient,
    verified_user_credentials: UserCredentials,
) -> None:
    """Assert managed public authorization clients must require user consent."""
    headers = await admin_auth_headers(client, verified_user_credentials)

    response = await client.post(
        ADMIN_CLIENTS_PATH,
        json={
            "name": "Unsafe Public Client",
            "grant_types": ["authorization_code"],
            "scopes": ["read"],
            "redirect_uris": ["https://client.example/callback"],
            "is_confidential": False,
            "requires_consent": False,
            "is_active": True,
        },
        headers=headers,
    )

    assert response.status_code == status.HTTP_400_BAD_REQUEST
    assert response.json()["code"] == "INVALID_OAUTH2_CLIENT"


@pytest.mark.asyncio
async def test_oauth2_client_create_requires_grant_types(
    client: httpx.AsyncClient,
    verified_user_credentials: UserCredentials,
) -> None:
    """Assert managed OAuth2 clients must declare at least one grant type."""
    headers = await admin_auth_headers(client, verified_user_credentials)

    response = await client.post(
        ADMIN_CLIENTS_PATH,
        json={
            "name": "Grantless Client",
            "grant_types": [],
            "scopes": ["read"],
            "redirect_uris": [],
            "is_confidential": False,
            "requires_consent": True,
            "is_active": True,
        },
        headers=headers,
    )

    assert response.status_code == status.HTTP_400_BAD_REQUEST
    assert response.json()["code"] == "INVALID_OAUTH2_CLIENT"


@pytest.mark.asyncio
@pytest.mark.negative
async def test_oauth2_client_create_rejects_unsupported_grant_type(
    client: httpx.AsyncClient,
    verified_user_credentials: UserCredentials,
) -> None:
    """Assert managed OAuth2 clients reject unsupported grant types."""
    headers = await admin_auth_headers(client, verified_user_credentials)

    response = await client.post(
        ADMIN_CLIENTS_PATH,
        json={
            "name": "Implicit Client",
            "grant_types": ["implicit"],
            "scopes": ["read"],
            "redirect_uris": [],
            "is_confidential": False,
            "requires_consent": True,
            "is_active": True,
        },
        headers=headers,
    )

    assert response.status_code == status.HTTP_422_UNPROCESSABLE_CONTENT


@pytest.mark.asyncio
@app_settings(
    oauth2={
        "authorization_code_enabled": False,
        "refresh_token_enabled": False,
        "client_credentials_enabled": False,
        "device_code_enabled": False,
        "oidc_enabled": False,
    }
)
@pytest.mark.negative
async def test_oauth2_client_routes_are_absent_without_enabled_grants(
    client: httpx.AsyncClient,
    verified_user_credentials: UserCredentials,
) -> None:
    """Assert client management is not mounted without an enabled grant."""
    headers = await admin_auth_headers(client, verified_user_credentials)
    response = await client.post(
        ADMIN_CLIENTS_PATH,
        json={
            "name": "Disabled Grant Client",
            "grant_types": ["client_credentials"],
            "scopes": ["service:read"],
            "redirect_uris": [],
            "is_confidential": True,
            "requires_consent": True,
            "is_active": True,
        },
        headers=headers,
    )

    assert response.status_code == status.HTTP_404_NOT_FOUND


@pytest.mark.asyncio
@pytest.mark.negative
async def test_replace_missing_oauth2_client_returns_not_found(
    client: httpx.AsyncClient,
    verified_user_credentials: UserCredentials,
) -> None:
    """Assert updates for missing managed clients return a 404."""
    headers = await admin_auth_headers(client, verified_user_credentials)

    response = await client.put(
        f"{ADMIN_CLIENTS_PATH}/missing-client",
        json={
            "name": "Missing",
            "grant_types": ["client_credentials"],
            "scopes": ["service:read"],
            "redirect_uris": [],
            "is_confidential": True,
            "requires_consent": True,
            "is_active": True,
            "user_organization_access": "unrestricted",
        },
        headers=headers,
    )

    assert response.status_code == status.HTTP_404_NOT_FOUND
    assert response.json()["code"] == "OAUTH2_CLIENT_NOT_FOUND"


@pytest.mark.asyncio
async def test_replace_public_client_with_confidential_requires_secret_rotation(
    client: httpx.AsyncClient,
    verified_user_credentials: UserCredentials,
) -> None:
    """Assert public clients cannot become confidential without a secret rotation."""
    headers = await admin_auth_headers(client, verified_user_credentials)
    create_response = await create_public_client(client, headers)
    assert create_response.status_code == status.HTTP_201_CREATED
    client_id = create_response.json()["client_id"]

    response = await client.put(
        f"{ADMIN_CLIENTS_PATH}/{client_id}",
        json={
            "name": "Needs Secret",
            "grant_types": ["client_credentials"],
            "scopes": ["service:read"],
            "redirect_uris": [],
            "is_confidential": True,
            "requires_consent": True,
            "is_active": True,
            "user_organization_access": "unrestricted",
        },
        headers=headers,
    )

    assert response.status_code == status.HTTP_400_BAD_REQUEST
    assert response.json()["code"] == "INVALID_OAUTH2_CLIENT"


@pytest.mark.asyncio
@pytest.mark.negative
async def test_oauth2_client_replacement_requires_user_organization_access(
    client: httpx.AsyncClient,
    verified_user_credentials: UserCredentials,
) -> None:
    """Keep the general client PUT contract a complete replacement."""
    headers = await admin_auth_headers(client, verified_user_credentials)
    create_response = await create_public_client(client, headers)
    assert create_response.status_code == status.HTTP_201_CREATED

    response = await client.put(
        f"{ADMIN_CLIENTS_PATH}/{create_response.json()['client_id']}",
        json={
            "name": "Incomplete replacement",
            "grant_types": ["authorization_code"],
            "scopes": ["read"],
            "redirect_uris": ["https://client.example/callback"],
            "is_confidential": False,
            "requires_consent": True,
            "is_active": True,
        },
        headers=headers,
    )

    assert response.status_code == status.HTTP_422_UNPROCESSABLE_CONTENT


@pytest.mark.asyncio
@pytest.mark.negative
async def test_oauth2_client_creation_rejects_blank_name(
    client: httpx.AsyncClient,
    verified_user_credentials: UserCredentials,
) -> None:
    """Reject OAuth2 client names without visible characters."""
    headers = await admin_auth_headers(client, verified_user_credentials)

    response = await client.post(
        ADMIN_CLIENTS_PATH,
        json={
            "name": "   ",
            "grant_types": ["authorization_code"],
            "redirect_uris": ["https://client.example/callback"],
        },
        headers=headers,
    )

    assert response.status_code == status.HTTP_422_UNPROCESSABLE_CONTENT


@pytest.mark.asyncio
@pytest.mark.negative
async def test_delete_missing_oauth2_client_returns_not_found(
    client: httpx.AsyncClient,
    verified_user_credentials: UserCredentials,
) -> None:
    """Assert deleting missing managed clients returns a 404."""
    headers = await admin_auth_headers(client, verified_user_credentials)

    response = await client.delete(
        f"{ADMIN_CLIENTS_PATH}/missing-client",
        headers=headers,
    )

    assert response.status_code == status.HTTP_404_NOT_FOUND
    assert response.json()["code"] == "OAUTH2_CLIENT_NOT_FOUND"


@pytest.mark.asyncio
async def test_oauth2_client_create_validates_authorization_code_redirects(
    client: httpx.AsyncClient,
    verified_user_credentials: UserCredentials,
) -> None:
    """Assert authorization-code clients must register redirect URIs."""
    headers = await admin_auth_headers(client, verified_user_credentials)

    response = await client.post(
        ADMIN_CLIENTS_PATH,
        json={
            "name": "Broken Client",
            "grant_types": ["authorization_code"],
            "scopes": [],
            "redirect_uris": [],
            "is_confidential": False,
            "is_active": True,
        },
        headers=headers,
    )

    assert response.status_code == status.HTTP_400_BAD_REQUEST


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "redirect_uri",
    [
        "client.example/callback",
        "https://client.example/callback#token",
        "http://client.example/callback",
    ],
)
@pytest.mark.negative
async def test_oauth2_client_create_rejects_unsafe_redirect_uris(
    client: httpx.AsyncClient,
    verified_user_credentials: UserCredentials,
    redirect_uri: str,
) -> None:
    """Assert OAuth2 client creation rejects unsafe redirect URI shapes."""
    headers = await admin_auth_headers(client, verified_user_credentials)

    response = await client.post(
        ADMIN_CLIENTS_PATH,
        json={
            "name": "Unsafe Client",
            "grant_types": ["authorization_code"],
            "scopes": [],
            "redirect_uris": [redirect_uri],
            "is_confidential": False,
            "is_active": True,
        },
        headers=headers,
    )

    assert response.status_code == status.HTTP_422_UNPROCESSABLE_CONTENT


@pytest.mark.asyncio
async def test_oauth2_client_create_allows_localhost_http_redirect_uri(
    client: httpx.AsyncClient,
    verified_user_credentials: UserCredentials,
) -> None:
    """Assert OAuth2 client creation allows localhost HTTP redirect URIs."""
    headers = await admin_auth_headers(client, verified_user_credentials)

    response = await client.post(
        ADMIN_CLIENTS_PATH,
        json={
            "name": "Local Client",
            "grant_types": ["authorization_code"],
            "scopes": [],
            "redirect_uris": ["http://localhost:5173/callback"],
            "is_confidential": False,
            "is_active": True,
        },
        headers=headers,
    )

    assert response.status_code == status.HTTP_201_CREATED
    assert response.json()["redirect_uris"] == ["http://localhost:5173/callback"]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "scope",
    [
        "",
        "read write",
        'read"write',
        "read\\write",
        "réad",
    ],
)
@pytest.mark.negative
async def test_oauth2_client_create_rejects_invalid_scope_names(
    client: httpx.AsyncClient,
    verified_user_credentials: UserCredentials,
    scope: str,
) -> None:
    """Assert OAuth2 client creation rejects malformed scope names."""
    headers = await admin_auth_headers(client, verified_user_credentials)

    response = await client.post(
        ADMIN_CLIENTS_PATH,
        json={
            "name": "Scoped Client",
            "grant_types": ["authorization_code"],
            "scopes": [scope],
            "redirect_uris": ["https://client.example/callback"],
            "is_confidential": False,
            "is_active": True,
        },
        headers=headers,
    )

    assert response.status_code == status.HTTP_422_UNPROCESSABLE_CONTENT
