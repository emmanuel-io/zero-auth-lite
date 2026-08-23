"""Black-box tests for operator user administration."""

import httpx
import pytest
from app.db.models.organization_membership import OrganizationMembershipDB
from app.db.models.user import UserDB
from app.identity.users.enums import OrganizationUserRole
from fastapi import FastAPI, status
from sqlalchemy import select, update

from tests.fixtures.auth import current_user_id_for_email, UserCredentials
from tests.routes.api.helpers import login_headers


pytestmark = pytest.mark.api

USERS_PATH = "/api/v1/admin/users"
ORGANIZATIONS_PATH = "/api/v1/admin/organizations"


@pytest.mark.asyncio
@pytest.mark.system
async def test_operator_can_manage_users_across_organizations(
    client: httpx.AsyncClient,
    verified_user_credentials: UserCredentials,
) -> None:
    """Assert operator CRUD can target an organization outside the operator's org."""
    headers = await login_headers(client, verified_user_credentials)
    organization_response = await client.post(
        ORGANIZATIONS_PATH,
        json={"name": "Managed Organization"},
        headers=headers,
    )
    assert organization_response.status_code == status.HTTP_201_CREATED
    organization_id = organization_response.json()["id"]

    create_response = await client.post(
        USERS_PATH,
        json={
            "organization_id": organization_id,
            "email": "managed@example.com",
            "first_name": "Managed",
        },
        headers=headers,
    )
    assert create_response.status_code == status.HTTP_201_CREATED
    user_id = create_response.json()["id"]

    list_response = await client.get(
        USERS_PATH,
        params={
            "organization_id": organization_id,
            "q": "managed",
            "operator": False,
            "email_verified": False,
            "sort": "-email_verified",
        },
    )
    read_response = await client.get(f"{USERS_PATH}/{user_id}")
    patch_response = await client.patch(
        f"{USERS_PATH}/{user_id}",
        json={
            "last_name": "Patched",
            "is_operator": True,
            "email_verified": True,
        },
        headers=headers,
    )
    replace_response = await client.put(
        f"{USERS_PATH}/{user_id}",
        json={
            "organization_id": organization_id,
            "email": "managed@example.com",
            "first_name": "Replacement",
            "last_name": "User",
            "is_active": True,
            "role": "member",
            "is_operator": False,
            "email_verified": True,
        },
        headers=headers,
    )
    delete_response = await client.delete(f"{USERS_PATH}/{user_id}", headers=headers)

    assert list_response.status_code == status.HTTP_200_OK
    assert list_response.json()["total"] == 1
    assert read_response.status_code == status.HTTP_200_OK
    assert read_response.json()["organization_id"] == organization_id
    assert read_response.json()["is_active"] is True
    assert read_response.json()["email_verified"] is False
    assert patch_response.status_code == status.HTTP_200_OK
    assert patch_response.json()["is_operator"] is True
    assert patch_response.json()["email_verified"] is True
    assert replace_response.status_code == status.HTTP_200_OK
    assert replace_response.json()["first_name"] == "Replacement"
    assert delete_response.status_code == status.HTTP_204_NO_CONTENT


@pytest.mark.asyncio
async def test_operator_can_resend_user_invitation(
    client: httpx.AsyncClient,
    verified_user_credentials: UserCredentials,
) -> None:
    """Expose invitation resend through the global operator control plane."""
    headers = await login_headers(client, verified_user_credentials)
    organization_response = await client.post(
        ORGANIZATIONS_PATH,
        json={"name": "Operator Reinvite Organization"},
        headers=headers,
    )
    create_response = await client.post(
        USERS_PATH,
        json={
            "organization_id": organization_response.json()["id"],
            "email": "operator-reinvite@example.com",
        },
        headers=headers,
    )

    response = await client.post(
        f"{USERS_PATH}/{create_response.json()['id']}/invitation",
        headers=headers,
    )

    assert response.status_code == status.HTTP_204_NO_CONTENT
    assert response.content == b""


@pytest.mark.asyncio
async def test_operator_without_organization_admin_role_can_manage_operators(
    app: FastAPI,
    client: httpx.AsyncClient,
    verified_user_credentials: UserCredentials,
) -> None:
    """Keep global operator authority independent from organization roles."""
    headers = await login_headers(client, verified_user_credentials)
    actor_response = await client.get(
        USERS_PATH,
        params={"q": verified_user_credentials.email},
    )
    actor = actor_response.json()["items"][0]
    target_response = await client.post(
        USERS_PATH,
        json={
            "organization_id": actor["organization_id"],
            "email": "protected-operator@example.com",
        },
        headers=headers,
    )
    assert target_response.status_code == status.HTTP_201_CREATED
    target_id = target_response.json()["id"]
    logout_response = await client.post(
        "/api/v1/sessions/logout",
        headers=headers,
    )
    assert logout_response.status_code == status.HTTP_204_NO_CONTENT

    async with app.state.core_session_factory() as db_session:
        await db_session.execute(
            update(OrganizationMembershipDB)
            .where(
                OrganizationMembershipDB.user_id
                == select(UserDB.id)
                .where(
                    UserDB.id
                    == current_user_id_for_email(verified_user_credentials.email)
                )
                .scalar_subquery()
            )
            .values(role=OrganizationUserRole.MEMBER)
        )
        await db_session.commit()
    headers = await login_headers(client, verified_user_credentials)

    promotion = await client.patch(
        f"{USERS_PATH}/{target_id}",
        json={"is_operator": True},
        headers=headers,
    )
    invitation = await client.post(
        f"{USERS_PATH}/{target_id}/invitation",
        headers=headers,
    )
    mutation = await client.patch(
        f"{USERS_PATH}/{target_id}",
        json={"last_name": "Managed"},
        headers=headers,
    )
    deletion = await client.delete(f"{USERS_PATH}/{target_id}", headers=headers)

    assert promotion.status_code == status.HTTP_200_OK
    assert promotion.json()["is_operator"] is True
    assert invitation.status_code == status.HTTP_204_NO_CONTENT
    assert mutation.status_code == status.HTTP_200_OK
    assert mutation.json()["last_name"] == "Managed"
    assert deletion.status_code == status.HTTP_204_NO_CONTENT


@pytest.mark.asyncio
async def test_operator_invitation_resend_requires_authentication(
    client: httpx.AsyncClient,
) -> None:
    """Reject anonymous invitation resend commands."""
    response = await client.post(f"{USERS_PATH}/usr_001P018WN3AT0/invitation")

    assert response.status_code == status.HTTP_401_UNAUTHORIZED


@pytest.mark.asyncio
@pytest.mark.parametrize("forbidden_field", ["password", "is_active", "email_verified"])
async def test_operator_user_invitation_rejects_direct_credentials_and_status(
    client: httpx.AsyncClient,
    verified_user_credentials: UserCredentials,
    forbidden_field: str,
) -> None:
    """Keep operator creation on the invitation-only lifecycle."""
    headers = await login_headers(client, verified_user_credentials)
    organization_response = await client.post(
        ORGANIZATIONS_PATH,
        json={"name": f"Invite {forbidden_field}"},
        headers=headers,
    )
    assert organization_response.status_code == status.HTTP_201_CREATED
    value: str | bool = "M4nagedSecret1!" if forbidden_field == "password" else True

    response = await client.post(
        USERS_PATH,
        json={
            "organization_id": organization_response.json()["id"],
            "email": f"{forbidden_field}@example.com",
            forbidden_field: value,
        },
        headers=headers,
    )

    assert response.status_code == status.HTTP_422_UNPROCESSABLE_CONTENT


@pytest.mark.asyncio
async def test_operator_user_list_validates_organization_id(
    client: httpx.AsyncClient,
    verified_user_credentials: UserCredentials,
) -> None:
    """Assert malformed organization filters are rejected before persistence access."""
    await login_headers(client, verified_user_credentials)

    response = await client.get(USERS_PATH, params={"organization_id": "invalid"})

    assert response.status_code == status.HTTP_422_UNPROCESSABLE_CONTENT


@pytest.mark.asyncio
@pytest.mark.negative
async def test_operator_user_list_rejects_inverted_created_range(
    client: httpx.AsyncClient,
    verified_user_credentials: UserCredentials,
) -> None:
    """Reject a created range whose lower bound follows its upper bound."""
    await login_headers(client, verified_user_credentials)

    response = await client.get(
        USERS_PATH,
        params={"created_from": "2026-08-20", "created_to": "2026-08-19"},
    )

    assert response.status_code == status.HTTP_400_BAD_REQUEST
    assert response.json()["code"] == "START_DATE_AFTER_END_DATE"


@pytest.mark.asyncio
async def test_operator_user_routes_require_authentication(
    client: httpx.AsyncClient,
) -> None:
    """Assert anonymous callers cannot enumerate users globally."""
    response = await client.get(USERS_PATH)

    assert response.status_code == status.HTTP_401_UNAUTHORIZED


@pytest.mark.asyncio
async def test_operator_cannot_remove_final_accessible_operator(
    client: httpx.AsyncClient,
    verified_user_credentials: UserCredentials,
) -> None:
    """Return a conflict for writes that would lock the server control plane."""
    headers = await login_headers(client, verified_user_credentials)
    users_response = await client.get(
        USERS_PATH,
        params={"q": verified_user_credentials.email},
    )
    assert users_response.status_code == status.HTTP_200_OK
    operator = users_response.json()["items"][0]
    user_path = f"{USERS_PATH}/{operator['id']}"

    for payload in (
        {"is_operator": False},
        {"is_active": False},
        {"email_verified": False},
    ):
        response = await client.patch(user_path, json=payload, headers=headers)
        assert response.status_code == status.HTTP_409_CONFLICT
        assert response.json()["message"] == (
            "At least one active, verified server operator is required."
        )

    replacement = await client.put(
        user_path,
        json={
            "organization_id": operator["organization_id"],
            "email": operator["email"],
            "first_name": operator["first_name"],
            "last_name": operator["last_name"],
            "is_active": operator["is_active"],
            "role": operator["role"],
            "is_operator": False,
            "email_verified": operator["email_verified"],
        },
        headers=headers,
    )
    deletion = await client.delete(user_path, headers=headers)

    assert replacement.status_code == status.HTTP_409_CONFLICT
    assert deletion.status_code == status.HTTP_409_CONFLICT
