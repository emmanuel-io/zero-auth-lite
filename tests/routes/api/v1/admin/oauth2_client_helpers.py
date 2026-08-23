"""Shared setup for OAuth2 client administration route tests."""

import httpx
from fastapi import status

from tests.fixtures.auth import login_browser, UserCredentials


ADMIN_CLIENTS_PATH = "/api/v1/admin/oauth2/clients"
DEFAULT_CLIENT_LIST_LIMIT = 20


async def admin_auth_headers(
    client: httpx.AsyncClient,
    credentials: UserCredentials,
) -> dict[str, str]:
    """Log in the admin test user and return CSRF-protected session headers."""
    response = await login_browser(client, credentials)
    assert response.status_code == status.HTTP_204_NO_CONTENT
    csrf_header = next(
        name for name in response.headers if name.lower().startswith("x-csrf")
    )
    return {
        "Origin": str(client.base_url).rstrip("/"),
        csrf_header: response.headers[csrf_header],
    }


async def create_public_client(
    client: httpx.AsyncClient,
    headers: dict[str, str],
) -> httpx.Response:
    """Create a public authorization-code OAuth2 client."""
    return await client.post(
        ADMIN_CLIENTS_PATH,
        json={
            "name": "Admin UI",
            "grant_types": ["authorization_code"],
            "scopes": ["read"],
            "redirect_uris": ["https://client.example/callback"],
            "is_confidential": False,
            "is_active": True,
        },
        headers=headers,
    )
