"""Black-box tests for OAuth2 client user-organization access."""

import httpx
import pytest
from fastapi import status

from tests.fixtures.auth import UserCredentials
from tests.routes.api.v1.server.oauth2_client_helpers import (
    create_public_client,
    operator_auth_headers,
    SERVER_CLIENTS_PATH,
)


pytestmark = pytest.mark.api


@pytest.mark.asyncio
@pytest.mark.system
async def test_operator_can_manage_user_organization_policy(
    client: httpx.AsyncClient,
    verified_user_credentials: UserCredentials,
) -> None:
    """Expose selected user organizations through the dedicated routes."""
    headers = await operator_auth_headers(client, verified_user_credentials)
    organization_response = await client.post(
        "/api/v1/server/organizations",
        json={"name": "Client Organization"},
        headers=headers,
    )
    organization_id = organization_response.json()["id"]
    client_response = await client.post(
        SERVER_CLIENTS_PATH,
        json={
            "name": "User policy UI",
            "grant_types": ["authorization_code"],
            "redirect_uris": ["https://client.example/callback"],
        },
        headers=headers,
    )
    client_id = client_response.json()["client_id"]

    update_response = await client.put(
        f"{SERVER_CLIENTS_PATH}/{client_id}/user-organizations",
        json={
            "user_organization_access": "selected",
            "organization_ids": [organization_id],
        },
        headers=headers,
    )
    read_response = await client.get(
        f"{SERVER_CLIENTS_PATH}/{client_id}/user-organizations"
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
    headers = await operator_auth_headers(client, verified_user_credentials)
    create_response = await create_public_client(client, headers)
    response = await client.put(
        f"{SERVER_CLIENTS_PATH}/{create_response.json()['client_id']}"
        "/user-organizations",
        json={
            "user_organization_access": "unrestricted",
            "organization_ids": ["00000000-0000-4000-8000-000000000000"],
        },
        headers=headers,
    )
    assert response.status_code == status.HTTP_409_CONFLICT
    assert response.json()["code"] == "OAUTH2_CLIENT_ORGANIZATION_ACCESS_CONFLICT"
    assert response.json()["details"] == [
        {
            "location": [],
            "message": (
                "Unrestricted user access does not accept organization assignments."
            ),
            "type": "oauth2_client_unrestricted_organizations_forbidden",
        }
    ]


@pytest.mark.asyncio
@pytest.mark.system
async def test_client_creation_applies_user_policy_and_assignments_atomically(
    client: httpx.AsyncClient,
    verified_user_credentials: UserCredentials,
) -> None:
    """Create a single-organization client without an incomplete policy state."""
    headers = await operator_auth_headers(client, verified_user_credentials)
    organization_response = await client.post(
        "/api/v1/server/organizations",
        json={"name": "Initial Client Organization"},
        headers=headers,
    )
    organization_id = organization_response.json()["id"]

    create_response = await client.post(
        SERVER_CLIENTS_PATH,
        json={
            "name": "Single Organization Client",
            "grant_types": ["authorization_code"],
            "redirect_uris": ["https://client.example/callback"],
            "user_organization_access": "single",
            "user_organization_ids": [organization_id],
        },
        headers=headers,
    )

    assert create_response.status_code == status.HTTP_201_CREATED
    client_id = create_response.json()["client_id"]
    policy_response = await client.get(
        f"{SERVER_CLIENTS_PATH}/{client_id}/user-organizations",
        headers=headers,
    )
    assert policy_response.json() == {
        "user_organization_access": "single",
        "organizations": [
            {
                "organization_id": organization_id,
                "name": "Initial Client Organization",
            }
        ],
    }
