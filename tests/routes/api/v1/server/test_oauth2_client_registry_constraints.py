"""Black-box constraint tests for the operator OAuth2 client registry."""

import httpx
import pytest
from fastapi import status

from tests.fixtures.auth import UserCredentials
from tests.fixtures.settings import app_settings
from tests.routes.api.v1.server.oauth2_client_helpers import (
    create_public_client,
    operator_auth_headers,
    SERVER_CLIENTS_PATH,
)


pytestmark = pytest.mark.api


@pytest.mark.asyncio
@pytest.mark.negative
async def test_general_client_replacement_rejects_machine_organization_policy(
    client: httpx.AsyncClient,
    verified_user_credentials: UserCredentials,
) -> None:
    """Keep machine mode and assignments on their atomic dedicated endpoint."""
    headers = await operator_auth_headers(client, verified_user_credentials)
    create_response = await create_public_client(client, headers)
    assert create_response.status_code == status.HTTP_201_CREATED

    response = await client.put(
        f"{SERVER_CLIENTS_PATH}/{create_response.json()['client_id']}",
        json={
            "name": "Unexpected Machine Update",
            "grant_types": ["authorization_code"],
            "scopes": ["read"],
            "redirect_uris": ["https://client.example/callback"],
            "is_confidential": False,
            "requires_consent": True,
            "is_active": True,
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
    headers = await operator_auth_headers(client, verified_user_credentials)

    response = await client.post(
        SERVER_CLIENTS_PATH,
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
    headers = await operator_auth_headers(client, verified_user_credentials)

    response = await client.post(
        SERVER_CLIENTS_PATH,
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
    assert response.json()["details"] == [
        {
            "location": [],
            "message": "Public authorization clients must require user consent.",
            "type": "public_authorization_clients_require_consent",
        }
    ]


@pytest.mark.asyncio
async def test_oauth2_client_create_requires_grant_types(
    client: httpx.AsyncClient,
    verified_user_credentials: UserCredentials,
) -> None:
    """Assert managed OAuth2 clients must declare at least one grant type."""
    headers = await operator_auth_headers(client, verified_user_credentials)

    response = await client.post(
        SERVER_CLIENTS_PATH,
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
    assert response.json()["details"] == [
        {
            "location": [],
            "message": "At least one grant type is required.",
            "type": "grant_types_required",
        }
    ]


@pytest.mark.asyncio
@pytest.mark.negative
async def test_oauth2_client_create_rejects_unsupported_grant_type(
    client: httpx.AsyncClient,
    verified_user_credentials: UserCredentials,
) -> None:
    """Assert managed OAuth2 clients reject unsupported grant types."""
    headers = await operator_auth_headers(client, verified_user_credentials)

    response = await client.post(
        SERVER_CLIENTS_PATH,
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
    headers = await operator_auth_headers(client, verified_user_credentials)
    response = await client.post(
        SERVER_CLIENTS_PATH,
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
    headers = await operator_auth_headers(client, verified_user_credentials)

    response = await client.put(
        f"{SERVER_CLIENTS_PATH}/00000000-0000-4000-8000-000000000000",
        json={
            "name": "Missing",
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
    assert response.json()["code"] == "OAUTH2_CLIENT_NOT_FOUND"


@pytest.mark.asyncio
async def test_replace_public_client_with_confidential_requires_secret_rotation(
    client: httpx.AsyncClient,
    verified_user_credentials: UserCredentials,
) -> None:
    """Assert public clients cannot become confidential without a secret rotation."""
    headers = await operator_auth_headers(client, verified_user_credentials)
    create_response = await create_public_client(client, headers)
    assert create_response.status_code == status.HTTP_201_CREATED
    client_id = create_response.json()["client_id"]

    response = await client.put(
        f"{SERVER_CLIENTS_PATH}/{client_id}",
        json={
            "name": "Needs Secret",
            "grant_types": ["client_credentials"],
            "scopes": ["service:read"],
            "redirect_uris": [],
            "is_confidential": True,
            "requires_consent": True,
            "is_active": True,
        },
        headers=headers,
    )

    assert response.status_code == status.HTTP_400_BAD_REQUEST
    assert response.json()["code"] == "INVALID_OAUTH2_CLIENT"


@pytest.mark.asyncio
@pytest.mark.negative
async def test_general_client_replacement_rejects_user_organization_policy(
    client: httpx.AsyncClient,
    verified_user_credentials: UserCredentials,
) -> None:
    """Keep user mode and assignments on their atomic dedicated endpoint."""
    headers = await operator_auth_headers(client, verified_user_credentials)
    create_response = await create_public_client(client, headers)
    assert create_response.status_code == status.HTTP_201_CREATED

    response = await client.put(
        f"{SERVER_CLIENTS_PATH}/{create_response.json()['client_id']}",
        json={
            "name": "Incomplete replacement",
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

    assert response.status_code == status.HTTP_422_UNPROCESSABLE_CONTENT


@pytest.mark.asyncio
@pytest.mark.negative
async def test_delete_missing_oauth2_client_returns_not_found(
    client: httpx.AsyncClient,
    verified_user_credentials: UserCredentials,
) -> None:
    """Assert deleting missing managed clients returns a 404."""
    headers = await operator_auth_headers(client, verified_user_credentials)

    response = await client.delete(
        f"{SERVER_CLIENTS_PATH}/00000000-0000-4000-8000-000000000000",
        headers=headers,
    )

    assert response.status_code == status.HTTP_404_NOT_FOUND
    assert response.json()["code"] == "OAUTH2_CLIENT_NOT_FOUND"
