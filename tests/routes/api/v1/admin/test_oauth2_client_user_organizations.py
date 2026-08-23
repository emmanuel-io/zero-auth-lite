"""Black-box tests for OAuth2 client user-organization access."""

import httpx
import pytest
from fastapi import status

from tests.fixtures.auth import UserCredentials
from tests.routes.api.v1.admin.oauth2_client_helpers import (
    admin_auth_headers,
    ADMIN_CLIENTS_PATH,
    create_public_client,
)


pytestmark = pytest.mark.api


@pytest.mark.asyncio
@pytest.mark.system
async def test_operator_can_manage_user_organization_policy(
    client: httpx.AsyncClient,
    verified_user_credentials: UserCredentials,
) -> None:
    """Expose selected user organizations through the dedicated routes."""
    headers = await admin_auth_headers(client, verified_user_credentials)
    organization_response = await client.post(
        "/api/v1/admin/organizations",
        json={"name": "Client Organization"},
        headers=headers,
    )
    organization_id = organization_response.json()["id"]
    client_response = await client.post(
        ADMIN_CLIENTS_PATH,
        json={
            "name": "Selected UI",
            "grant_types": ["authorization_code"],
            "redirect_uris": ["https://client.example/callback"],
            "user_organization_access": "selected",
        },
        headers=headers,
    )
    client_id = client_response.json()["client_id"]

    update_response = await client.put(
        f"{ADMIN_CLIENTS_PATH}/{client_id}/user-organizations",
        json={"organization_ids": [organization_id]},
        headers=headers,
    )
    read_response = await client.get(
        f"{ADMIN_CLIENTS_PATH}/{client_id}/user-organizations"
    )

    assert update_response.status_code == status.HTTP_200_OK
    assert update_response.json()["user_organization_access"] == "selected"
    assert update_response.json()["organizations"] == [
        {"organization_id": organization_id, "name": "Client Organization"}
    ]
    assert read_response.json() == update_response.json()


@pytest.mark.asyncio
@pytest.mark.negative
async def test_organization_access_conflict_uses_canonical_error_code(
    client: httpx.AsyncClient,
    verified_user_credentials: UserCredentials,
) -> None:
    """Expose one vocabulary for organization-access policy conflicts."""
    headers = await admin_auth_headers(client, verified_user_credentials)
    create_response = await create_public_client(client, headers)
    response = await client.put(
        f"{ADMIN_CLIENTS_PATH}/{create_response.json()['client_id']}"
        "/user-organizations",
        json={"organization_ids": ["org_001P018WN3AT0"]},
        headers=headers,
    )
    assert response.status_code == status.HTTP_409_CONFLICT
    assert response.json()["code"] == "OAUTH2_CLIENT_ORGANIZATION_ACCESS_CONFLICT"
