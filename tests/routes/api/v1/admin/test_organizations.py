"""Black-box tests for operator organization administration."""

import httpx
import pytest
from fastapi import status

from tests.fixtures.auth import UserCredentials
from tests.routes.api.helpers import login_headers


pytestmark = pytest.mark.api

ORGANIZATIONS_PATH = "/api/v1/admin/organizations"
EXPECTED_ORGANIZATION_COUNT = 2


@pytest.mark.asyncio
@pytest.mark.system
async def test_operator_can_manage_organizations(
    client: httpx.AsyncClient,
    verified_user_credentials: UserCredentials,
) -> None:
    """Assert operators can list, create, read, and update global organizations."""
    headers = await login_headers(client, verified_user_credentials)

    create_response = await client.post(
        ORGANIZATIONS_PATH,
        json={"name": "Second Organization"},
        headers=headers,
    )
    assert create_response.status_code == status.HTTP_201_CREATED
    organization_id = create_response.json()["id"]

    list_response = await client.get(
        ORGANIZATIONS_PATH, params={"offset": 0, "limit": 1}
    )
    read_response = await client.get(f"{ORGANIZATIONS_PATH}/{organization_id}")
    patch_response = await client.patch(
        f"{ORGANIZATIONS_PATH}/{organization_id}",
        json={"name": "Updated Organization"},
        headers=headers,
    )

    assert list_response.status_code == status.HTTP_200_OK
    assert list_response.json()["limit"] == 1
    assert list_response.json()["total"] == EXPECTED_ORGANIZATION_COUNT
    assert read_response.status_code == status.HTTP_200_OK
    assert read_response.json()["name"] == "Second Organization"
    assert patch_response.status_code == status.HTTP_200_OK
    assert patch_response.json()["name"] == "Updated Organization"


@pytest.mark.asyncio
async def test_operator_organization_routes_require_authentication(
    client: httpx.AsyncClient,
) -> None:
    """Assert anonymous callers cannot access the server control plane."""
    response = await client.get(ORGANIZATIONS_PATH)

    assert response.status_code == status.HTTP_401_UNAUTHORIZED


@pytest.mark.asyncio
async def test_operator_organization_list_validates_pagination(
    client: httpx.AsyncClient,
    verified_user_credentials: UserCredentials,
) -> None:
    """Assert pagination limits are enforced by typed query parameters."""
    await login_headers(client, verified_user_credentials)

    response = await client.get(ORGANIZATIONS_PATH, params={"limit": 0})

    assert response.status_code == status.HTTP_422_UNPROCESSABLE_CONTENT
