"""Black-box tests for `/api/v1/me` profile routes."""

import httpx
import pytest
from fastapi import status

from tests.fixtures.auth import login_browser, UserCredentials
from tests.routes.api.helpers import login_headers


pytestmark = pytest.mark.api
NEW_PASSWORD = "N3wSecretPass2!"  # noqa: S105


@pytest.mark.asyncio
async def test_user_can_read_and_patch_current_profile(
    client: httpx.AsyncClient,
    verified_user_credentials: UserCredentials,
) -> None:
    """Assert profile reads and partial updates use the authenticated identity."""
    headers = await login_headers(client, verified_user_credentials)

    read_response = await client.get("/api/v1/me")
    patch_response = await client.patch(
        "/api/v1/me",
        json={"first_name": "Updated", "last_name": "Profile"},
        headers=headers,
    )

    assert read_response.status_code == status.HTTP_200_OK
    read_payload = read_response.json()
    assert read_payload["email"] == verified_user_credentials.email
    assert read_payload["organization"] == {"name": "Test Organization"}
    assert {"id", "user_id", "organization_id", "is_operator"}.isdisjoint(read_payload)
    assert patch_response.status_code == status.HTTP_200_OK
    patch_payload = patch_response.json()
    assert patch_payload["first_name"] == "Updated"
    assert patch_payload["last_name"] == "Profile"
    assert patch_payload["organization"] == {"name": "Test Organization"}
    assert {"id", "user_id", "organization_id", "is_operator"}.isdisjoint(patch_payload)


@pytest.mark.asyncio
async def test_current_profile_mutation_uses_patch_only(
    client: httpx.AsyncClient,
    verified_user_credentials: UserCredentials,
) -> None:
    """Expose one partial-update contract for the current profile."""
    headers = await login_headers(client, verified_user_credentials)

    response = await client.put(
        "/api/v1/me",
        json={
            "email": verified_user_credentials.email,
            "first_name": "Replacement",
            "last_name": "User",
        },
        headers=headers,
    )

    assert response.status_code == status.HTTP_405_METHOD_NOT_ALLOWED


@pytest.mark.asyncio
async def test_user_changes_password_through_dedicated_route(
    client: httpx.AsyncClient,
    verified_user_credentials: UserCredentials,
) -> None:
    """Verify the old password, change it, and revoke the current browser session."""
    headers = await login_headers(client, verified_user_credentials)
    new_password = NEW_PASSWORD

    response = await client.post(
        "/api/v1/me/password",
        json={
            "current_password": verified_user_credentials.password,
            "new_password": new_password,
        },
        headers=headers,
    )
    old_login = await login_browser(
        client,
        verified_user_credentials,
    )
    new_login = await login_browser(
        client,
        UserCredentials(
            email=verified_user_credentials.email,
            password=new_password,
        ),
    )

    assert response.status_code == status.HTTP_204_NO_CONTENT
    assert old_login.status_code == status.HTTP_401_UNAUTHORIZED
    assert new_login.status_code == status.HTTP_204_NO_CONTENT


@pytest.mark.asyncio
@pytest.mark.negative
async def test_password_change_rejects_wrong_current_password(
    client: httpx.AsyncClient,
    verified_user_credentials: UserCredentials,
) -> None:
    """Leave the credential unchanged when current-password verification fails."""
    headers = await login_headers(client, verified_user_credentials)

    response = await client.post(
        "/api/v1/me/password",
        json={
            "current_password": "Wr0ngCurrentPass!",
            "new_password": "N3wSecretPass2!",
        },
        headers=headers,
    )

    assert response.status_code == status.HTTP_401_UNAUTHORIZED
    assert response.json()["message"] == "Invalid password"


@pytest.mark.asyncio
@pytest.mark.negative
async def test_profile_write_rejects_admin_fields(
    client: httpx.AsyncClient,
    verified_user_credentials: UserCredentials,
) -> None:
    """Assert users cannot grant themselves administrative roles."""
    headers = await login_headers(client, verified_user_credentials)

    response = await client.patch(
        "/api/v1/me",
        json={"is_operator": True},
        headers=headers,
    )

    assert response.status_code == status.HTTP_422_UNPROCESSABLE_CONTENT


@pytest.mark.asyncio
@pytest.mark.negative
@pytest.mark.parametrize("field", ["email", "first_name", "last_name"])
async def test_profile_write_rejects_explicit_nulls(
    client: httpx.AsyncClient,
    verified_user_credentials: UserCredentials,
    field: str,
) -> None:
    """Reject nulls before they can reach non-null relational columns."""
    headers = await login_headers(client, verified_user_credentials)

    response = await client.patch(
        "/api/v1/me",
        json={field: None},
        headers=headers,
    )

    assert response.status_code == status.HTTP_422_UNPROCESSABLE_CONTENT


@pytest.mark.asyncio
@pytest.mark.negative
async def test_profile_write_rejects_an_existing_email(
    client: httpx.AsyncClient,
    verified_user_credentials: UserCredentials,
) -> None:
    """Expose the canonical conflict when a profile claims another email."""
    registration = await client.post(
        "/api/v1/auth/register",
        json={
            "email": "other-profile@example.com",
            "password": "S3cretPass1!",
            "organization_name": "Other Profile Organization",
        },
    )
    assert registration.status_code == status.HTTP_201_CREATED
    headers = await login_headers(client, verified_user_credentials)

    response = await client.patch(
        "/api/v1/me",
        json={"email": "other-profile@example.com"},
        headers=headers,
    )

    assert response.status_code == status.HTTP_409_CONFLICT
    assert response.json()["code"] == "ALREADY_EXISTS"


@pytest.mark.asyncio
@pytest.mark.negative
async def test_user_can_delete_current_profile(
    client: httpx.AsyncClient,
    verified_user_credentials: UserCredentials,
) -> None:
    """Assert the last organization administrator cannot delete their identity."""
    headers = await login_headers(client, verified_user_credentials)

    delete_response = await client.delete("/api/v1/me", headers=headers)
    read_response = await client.get("/api/v1/me")

    assert delete_response.status_code == status.HTTP_409_CONFLICT
    assert delete_response.json()["code"] == "LAST_ACTIVE_OPERATOR"
    assert delete_response.json()["message"] == (
        "At least one active, verified server operator is required."
    )
    assert read_response.status_code == status.HTTP_200_OK


@pytest.mark.asyncio
@pytest.mark.negative
async def test_profile_requires_authentication(client: httpx.AsyncClient) -> None:
    """Assert anonymous callers cannot read a profile."""
    response = await client.get("/api/v1/me")

    assert response.status_code == status.HTTP_401_UNAUTHORIZED
