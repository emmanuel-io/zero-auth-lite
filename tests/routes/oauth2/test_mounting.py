"""Black-box HTTP tests for OAuth2 route mounting."""

import httpx
import pytest
from fastapi import status

from tests.fixtures.settings import app_settings


pytestmark = pytest.mark.api


@pytest.mark.asyncio
async def test_oauth2_routes_are_reachable_when_enabled(
    client: httpx.AsyncClient,
) -> None:
    """Assert a few canonical OAuth2 routes are mounted in the live app."""
    metadata_response = await client.get("/.well-known/oauth-authorization-server")
    jwks_response = await client.get("/oauth2/jwks.json")
    token_response = await client.post("/oauth2/token")

    assert metadata_response.status_code == status.HTTP_200_OK
    assert jwks_response.status_code == status.HTTP_200_OK
    assert token_response.status_code == status.HTTP_400_BAD_REQUEST


@pytest.mark.asyncio
@app_settings(
    oauth2={
        "authorization_code_enabled": False,
        "refresh_token_enabled": False,
        "client_credentials_enabled": False,
        "device_code_enabled": False,
        "oidc_enabled": False,
        "jwks_enabled": False,
    }
)
async def test_oauth2_routes_are_hidden_when_disabled(
    client: httpx.AsyncClient,
) -> None:
    """Assert disabling OAuth2 removes the protocol mount without harming health."""
    metadata_response = await client.get("/.well-known/oauth-authorization-server")
    jwks_response = await client.get("/oauth2/jwks.json")
    token_response = await client.post("/oauth2/token")
    health_response = await client.get("/health")

    assert metadata_response.status_code == status.HTTP_404_NOT_FOUND
    assert jwks_response.status_code == status.HTTP_404_NOT_FOUND
    assert token_response.status_code == status.HTTP_404_NOT_FOUND
    assert health_response.status_code == status.HTTP_200_OK


@pytest.mark.asyncio
@app_settings(oauth2={"oidc_enabled": False, "jwks_enabled": False})
async def test_optional_oidc_routes_are_hidden_when_disabled(
    client: httpx.AsyncClient,
) -> None:
    """Assert disabled OIDC and JWKS surfaces are absent from the live app."""
    userinfo_response = await client.get("/oauth2/userinfo")
    jwks_response = await client.get("/oauth2/jwks.json")

    assert userinfo_response.status_code == status.HTTP_404_NOT_FOUND
    assert jwks_response.status_code == status.HTTP_404_NOT_FOUND
