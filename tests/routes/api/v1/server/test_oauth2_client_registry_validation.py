"""Black-box input-validation tests for the operator OAuth2 client registry."""

import httpx
import pytest
from fastapi import status

from tests.fixtures.auth import UserCredentials
from tests.routes.api.v1.server.oauth2_client_helpers import (
    operator_auth_headers,
    SERVER_CLIENTS_PATH,
)


pytestmark = pytest.mark.api


@pytest.mark.asyncio
@pytest.mark.negative
async def test_oauth2_client_creation_rejects_blank_name(
    client: httpx.AsyncClient,
    verified_user_credentials: UserCredentials,
) -> None:
    """Reject OAuth2 client names without visible characters."""
    headers = await operator_auth_headers(client, verified_user_credentials)

    response = await client.post(
        SERVER_CLIENTS_PATH,
        json={
            "name": "   ",
            "grant_types": ["authorization_code"],
            "redirect_uris": ["https://client.example/callback"],
        },
        headers=headers,
    )

    assert response.status_code == status.HTTP_422_UNPROCESSABLE_CONTENT


@pytest.mark.asyncio
async def test_oauth2_client_create_validates_authorization_code_redirects(
    client: httpx.AsyncClient,
    verified_user_credentials: UserCredentials,
) -> None:
    """Assert authorization-code clients must register redirect URIs."""
    headers = await operator_auth_headers(client, verified_user_credentials)

    response = await client.post(
        SERVER_CLIENTS_PATH,
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
    headers = await operator_auth_headers(client, verified_user_credentials)

    response = await client.post(
        SERVER_CLIENTS_PATH,
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
    headers = await operator_auth_headers(client, verified_user_credentials)

    response = await client.post(
        SERVER_CLIENTS_PATH,
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
    headers = await operator_auth_headers(client, verified_user_credentials)

    response = await client.post(
        SERVER_CLIENTS_PATH,
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
