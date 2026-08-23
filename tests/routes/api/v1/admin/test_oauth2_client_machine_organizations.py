"""Black-box tests for OAuth2 client machine-organization access."""

import httpx
import pytest
from fastapi import status

from tests.fixtures.auth import UserCredentials
from tests.routes.api.v1.admin.oauth2_client_helpers import (
    admin_auth_headers,
    ADMIN_CLIENTS_PATH,
)


pytestmark = pytest.mark.api


@pytest.mark.asyncio
@pytest.mark.system
async def test_operator_can_manage_machine_organization_policy(
    client: httpx.AsyncClient,
    verified_user_credentials: UserCredentials,
) -> None:
    """Expose machine organization policy through the dedicated routes."""
    headers = await admin_auth_headers(client, verified_user_credentials)
    organization_response = await client.post(
        "/api/v1/admin/organizations",
        json={"name": "Machine Client Organization"},
        headers=headers,
    )
    organization_id = organization_response.json()["id"]
    client_response = await client.post(
        ADMIN_CLIENTS_PATH,
        json={
            "name": "Scoped Service",
            "grant_types": ["client_credentials"],
            "scopes": ["organization:read"],
            "is_confidential": True,
        },
        headers=headers,
    )
    client_id = client_response.json()["client_id"]

    update_response = await client.put(
        f"{ADMIN_CLIENTS_PATH}/{client_id}/machine-organizations",
        json={
            "machine_organization_access": "single",
            "organization_ids": [organization_id],
        },
        headers=headers,
    )
    read_response = await client.get(
        f"{ADMIN_CLIENTS_PATH}/{client_id}/machine-organizations"
    )

    assert update_response.status_code == status.HTTP_200_OK
    assert update_response.json()["machine_organization_access"] == "single"
    assert update_response.json()["organization_ids"] == [organization_id]
    assert read_response.json() == update_response.json()
