"""Black-box tests for `/api/v1/organization/users` administration."""

import re
from datetime import datetime, UTC

import httpx
import pytest
from app.api.dependencies.ids import format_user_id
from app.db.models.auth_event import AuthEventOutboxDB
from app.db.models.organization import OrganizationDB
from app.db.models.organization_membership import OrganizationMembershipDB
from app.db.models.user import UserDB, UserEmailDB
from app.identity.users.enums import OrganizationUserRole, UserEmailStatus
from app.public_ids import PUBLIC_ID_PAYLOAD_PATTERN
from app.security.permissions import Permission
from fastapi import FastAPI, status
from sqlalchemy import func, select, update

from tests.fixtures.auth import (
    current_user_id_for_email,
    issue_user_token,
    UserCredentials,
)
from tests.routes.api.helpers import login_headers


pytestmark = pytest.mark.api

USERS_PATH = "/api/v1/organization/users"
EXPECTED_INVITATION_EVENT_COUNT = 2


@pytest.mark.asyncio
@pytest.mark.system
async def test_organization_admin_can_manage_user_lifecycle(
    client: httpx.AsyncClient,
    verified_user_credentials: UserCredentials,
) -> None:
    """Assert organization administrators can create, read, update, and delete users."""
    headers = await login_headers(client, verified_user_credentials)
    create_response = await client.post(
        USERS_PATH,
        json={
            "email": "member@example.com",
            "password": "M3mberSecret1!",
            "first_name": "Initial",
        },
        headers=headers,
    )
    assert create_response.status_code == status.HTTP_201_CREATED
    user_id = create_response.json()["id"]
    assert re.fullmatch(rf"usr_{PUBLIC_ID_PAYLOAD_PATTERN}", user_id)

    list_response = await client.get(
        USERS_PATH,
        params={
            "q": "member",
            "active": True,
            "email_verified": False,
            "sort": "email_verified",
        },
    )
    read_response = await client.get(f"{USERS_PATH}/{user_id}")
    patch_response = await client.patch(
        f"{USERS_PATH}/{user_id}",
        json={"last_name": "Patched"},
        headers=headers,
    )
    replace_response = await client.put(
        f"{USERS_PATH}/{user_id}",
        json={
            "email": "member@example.com",
            "first_name": "Replacement",
            "last_name": "User",
            "is_active": True,
            "role": "member",
        },
        headers=headers,
    )
    delete_response = await client.delete(f"{USERS_PATH}/{user_id}", headers=headers)
    missing_response = await client.get(f"{USERS_PATH}/{user_id}")

    assert list_response.status_code == status.HTTP_200_OK
    assert list_response.json()["total"] == 1
    assert [item["id"] for item in list_response.json()["items"]] == [user_id]
    assert read_response.status_code == status.HTTP_200_OK
    assert read_response.json()["id"] == user_id
    assert patch_response.status_code == status.HTTP_200_OK
    assert patch_response.json()["last_name"] == "Patched"
    assert replace_response.status_code == status.HTTP_200_OK
    assert replace_response.json()["first_name"] == "Replacement"
    assert replace_response.json()["email_verified"] is False
    assert delete_response.status_code == status.HTTP_204_NO_CONTENT
    assert missing_response.status_code == status.HTTP_404_NOT_FOUND


@pytest.mark.asyncio
async def test_organization_admin_can_resend_user_invitation(
    app: FastAPI,
    client: httpx.AsyncClient,
    verified_user_credentials: UserCredentials,
) -> None:
    """Expose invitation resend as an explicit organization-admin command."""
    headers = await login_headers(client, verified_user_credentials)
    create_response = await client.post(
        USERS_PATH,
        json={"email": "organization-reinvite@example.com"},
        headers=headers,
    )
    assert create_response.status_code == status.HTTP_201_CREATED
    user_id = create_response.json()["id"]

    response = await client.post(
        f"{USERS_PATH}/{user_id}/invitation",
        headers=headers,
    )

    async with app.state.core_session_factory() as db_session:
        event_count = await db_session.scalar(
            select(func.count())
            .select_from(AuthEventOutboxDB)
            .where(AuthEventOutboxDB.event_type == "auth.invite_created")
        )

    assert response.status_code == status.HTTP_204_NO_CONTENT
    assert response.content == b""
    assert event_count == EXPECTED_INVITATION_EVENT_COUNT


@pytest.mark.asyncio
@pytest.mark.negative
async def test_organization_user_api_hides_and_cannot_mutate_operator_role(
    app: FastAPI,
    client: httpx.AsyncClient,
    verified_user_credentials: UserCredentials,
) -> None:
    """Keep operator accounts outside the organization user write contract."""
    headers = await login_headers(client, verified_user_credentials)
    create_response = await client.post(
        USERS_PATH,
        json={"email": "organization-operator@example.com"},
        headers=headers,
    )
    assert create_response.status_code == status.HTTP_201_CREATED
    user_id = create_response.json()["id"]
    async with app.state.core_session_factory() as db_session:
        await db_session.execute(
            update(UserDB)
            .where(
                UserDB.id
                == current_user_id_for_email("organization-operator@example.com")
            )
            .values(is_operator=True)
        )
        await db_session.commit()

    read_response = await client.get(f"{USERS_PATH}/{user_id}")
    role_write = await client.patch(
        f"{USERS_PATH}/{user_id}",
        json={"is_operator": False},
        headers=headers,
    )
    profile_write = await client.patch(
        f"{USERS_PATH}/{user_id}",
        json={"last_name": "Forbidden"},
        headers=headers,
    )
    deletion = await client.delete(f"{USERS_PATH}/{user_id}", headers=headers)

    assert read_response.status_code == status.HTTP_200_OK
    assert "is_operator" not in read_response.json()
    assert role_write.status_code == status.HTTP_422_UNPROCESSABLE_CONTENT
    assert profile_write.status_code == status.HTTP_403_FORBIDDEN
    assert deletion.status_code == status.HTTP_403_FORBIDDEN


@pytest.mark.asyncio
@pytest.mark.negative
async def test_organization_invitation_resend_rejects_inactive_user(
    app: FastAPI,
    client: httpx.AsyncClient,
    verified_user_credentials: UserCredentials,
) -> None:
    """Keep invitation resend separate from account reactivation."""
    headers = await login_headers(client, verified_user_credentials)
    create_response = await client.post(
        USERS_PATH,
        json={"email": "inactive-reinvite@example.com"},
        headers=headers,
    )
    user_id = create_response.json()["id"]
    async with app.state.core_session_factory() as db_session:
        await db_session.execute(
            update(UserDB)
            .where(
                UserDB.id == current_user_id_for_email("inactive-reinvite@example.com")
            )
            .values(is_active=False)
        )
        await db_session.commit()

    response = await client.post(
        f"{USERS_PATH}/{user_id}/invitation",
        headers=headers,
    )

    assert response.status_code == status.HTTP_409_CONFLICT
    assert response.json()["message"] == (
        "An invitation cannot be sent to an inactive user."
    )


@pytest.mark.asyncio
@pytest.mark.negative
async def test_organization_invitation_resend_hides_other_organization_user(
    client: httpx.AsyncClient,
    verified_user_credentials: UserCredentials,
) -> None:
    """Return not found when an invitation target belongs to another organization."""
    headers = await login_headers(client, verified_user_credentials)
    organization_response = await client.post(
        "/api/v1/admin/organizations",
        json={"name": "Other Invitation Organization"},
        headers=headers,
    )
    create_response = await client.post(
        "/api/v1/admin/users",
        json={
            "organization_id": organization_response.json()["id"],
            "email": "other-organization-reinvite@example.com",
        },
        headers=headers,
    )

    response = await client.post(
        f"{USERS_PATH}/{create_response.json()['id']}/invitation",
        headers=headers,
    )

    assert response.status_code == status.HTTP_404_NOT_FOUND


@pytest.mark.asyncio
async def test_organization_user_routes_require_authentication(
    client: httpx.AsyncClient,
) -> None:
    """Assert anonymous callers cannot enumerate organization users."""
    response = await client.get(USERS_PATH)

    assert response.status_code == status.HTTP_401_UNAUTHORIZED


@pytest.mark.asyncio
@pytest.mark.negative
async def test_organization_user_list_rejects_inverted_created_range(
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
@pytest.mark.negative
@pytest.mark.parametrize("is_operator", [False, True])
async def test_organization_user_routes_require_explicit_organization_admin_role(
    app: FastAPI,
    client: httpx.AsyncClient,
    verified_user_credentials: UserCredentials,
    *,
    is_operator: bool,
) -> None:
    """Reject members and operators that lack the organization-admin role."""
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
        await db_session.execute(
            update(UserDB)
            .where(
                UserDB.id == current_user_id_for_email(verified_user_credentials.email)
            )
            .values(is_operator=is_operator)
        )
        await db_session.commit()
    await login_headers(client, verified_user_credentials)

    response = await client.get(USERS_PATH)

    assert response.status_code == status.HTTP_403_FORBIDDEN
    assert response.json()["code"] == "FORBIDDEN_OPERATION"


@pytest.mark.asyncio
@pytest.mark.negative
async def test_organization_user_write_requires_csrf(
    client: httpx.AsyncClient,
    verified_user_credentials: UserCredentials,
) -> None:
    """Reject browser-session writes without matching CSRF proof."""
    csrf_headers = await login_headers(client, verified_user_credentials)

    missing_response = await client.post(
        USERS_PATH,
        json={"email": "member@example.com", "password": "M3mberSecret1!"},
    )
    csrf_header_name = next(
        name for name in csrf_headers if name.lower().startswith("x-csrf")
    )
    invalid_response = await client.post(
        USERS_PATH,
        json={"email": "member@example.com", "password": "M3mberSecret1!"},
        headers={**csrf_headers, csrf_header_name: "invalid-csrf-proof"},
    )

    assert missing_response.status_code == status.HTTP_403_FORBIDDEN
    assert invalid_response.status_code == status.HTTP_403_FORBIDDEN


@pytest.mark.asyncio
@pytest.mark.negative
async def test_organization_admin_cannot_set_verification_state(
    client: httpx.AsyncClient,
    verified_user_credentials: UserCredentials,
) -> None:
    """Reject verification state on every organization-admin user write contract."""
    headers = await login_headers(client, verified_user_credentials)
    create_response = await client.post(
        USERS_PATH,
        json={
            "email": "member@example.com",
            "password": "M3mberSecret1!",
            "email_verified": True,
        },
        headers=headers,
    )
    valid_create = await client.post(
        USERS_PATH,
        json={"email": "member@example.com", "password": "M3mberSecret1!"},
        headers=headers,
    )
    assert valid_create.status_code == status.HTTP_201_CREATED
    user_id = valid_create.json()["id"]

    patch_response = await client.patch(
        f"{USERS_PATH}/{user_id}",
        json={"email_verified": True},
        headers=headers,
    )
    replace_response = await client.put(
        f"{USERS_PATH}/{user_id}",
        json={
            "email": "member@example.com",
            "first_name": "Member",
            "last_name": "User",
            "is_active": True,
            "role": "member",
            "email_verified": True,
        },
        headers=headers,
    )

    assert create_response.status_code == status.HTTP_422_UNPROCESSABLE_CONTENT
    assert patch_response.status_code == status.HTTP_422_UNPROCESSABLE_CONTENT
    assert replace_response.status_code == status.HTTP_422_UNPROCESSABLE_CONTENT


@pytest.mark.asyncio
@pytest.mark.negative
async def test_organization_user_routes_require_matching_oauth2_scope(
    app: FastAPI,
    client: httpx.AsyncClient,
    verified_user_credentials: UserCredentials,
) -> None:
    """Reject an OAuth2 token that lacks the organization-user read scope."""
    token_response = await issue_user_token(app, client, verified_user_credentials)
    assert token_response.status_code == status.HTTP_200_OK

    response = await client.get(
        USERS_PATH,
        headers={"Authorization": f"Bearer {token_response.json()['access_token']}"},
    )

    assert response.status_code == status.HTTP_403_FORBIDDEN


@pytest.mark.asyncio
async def test_organization_admin_bearer_can_read_with_organization_scope(
    app: FastAPI,
    client: httpx.AsyncClient,
    verified_user_credentials: UserCredentials,
) -> None:
    """Authorize organization administration with organization:read and admin role."""
    token_response = await issue_user_token(
        app,
        client,
        verified_user_credentials,
        scope=Permission.ORGANIZATION_READ.value,
    )
    assert token_response.status_code == status.HTTP_200_OK
    client.cookies.clear()

    response = await client.get(
        USERS_PATH,
        headers={"Authorization": f"Bearer {token_response.json()['access_token']}"},
    )

    assert response.status_code == status.HTTP_200_OK


@pytest.mark.asyncio
async def test_organization_admin_bearer_can_resend_invitation_with_write_scope(
    app: FastAPI,
    client: httpx.AsyncClient,
    verified_user_credentials: UserCredentials,
) -> None:
    """Authorize invitation resend with organization:write and the admin role."""
    headers = await login_headers(client, verified_user_credentials)
    create_response = await client.post(
        USERS_PATH,
        json={"email": "scoped-reinvite@example.com"},
        headers=headers,
    )
    token_response = await issue_user_token(
        app,
        client,
        verified_user_credentials,
        scope=Permission.ORGANIZATION_WRITE.value,
    )
    assert token_response.status_code == status.HTTP_200_OK
    client.cookies.clear()

    response = await client.post(
        f"{USERS_PATH}/{create_response.json()['id']}/invitation",
        headers={"Authorization": f"Bearer {token_response.json()['access_token']}"},
    )

    assert response.status_code == status.HTTP_204_NO_CONTENT


@pytest.mark.asyncio
@pytest.mark.negative
async def test_organization_user_route_hides_other_organization_user(
    app: FastAPI,
    client: httpx.AsyncClient,
    verified_user_credentials: UserCredentials,
) -> None:
    """Return not found for a valid user identifier owned by another organization."""
    async with app.state.core_session_factory() as db_session:
        other_organization = OrganizationDB(name="Other Organization")
        db_session.add(other_organization)
        await db_session.flush()
        other_user = UserDB(
            hashed_password=app.state.password_hasher.hash("OtherSecret1!"),
            is_active=True,
        )
        db_session.add(other_user)
        await db_session.flush()
        db_session.add_all(
            [
                UserEmailDB(
                    user_id=other_user.id,
                    email="other-organization-user@example.com",
                    normalized_email="other-organization-user@example.com",
                    status=UserEmailStatus.CURRENT,
                    verified_at=datetime.now(UTC),
                ),
                OrganizationMembershipDB(
                    user_id=other_user.id,
                    organization_id=other_organization.id,
                    role=OrganizationUserRole.MEMBER,
                ),
            ]
        )
        other_user_id = format_user_id(other_user.public_id)
        await db_session.commit()
    await login_headers(client, verified_user_credentials)

    response = await client.get(f"{USERS_PATH}/{other_user_id}")

    assert response.status_code == status.HTTP_404_NOT_FOUND


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "user_id",
    ["not-a-user-id", "usr_1234567890123456789", "usr_128ggyhyyk08n"],
)
async def test_organization_user_path_rejects_invalid_public_id(
    client: httpx.AsyncClient,
    verified_user_credentials: UserCredentials,
    user_id: str,
) -> None:
    """Assert malformed public identifiers fail at the HTTP boundary."""
    await login_headers(client, verified_user_credentials)

    response = await client.get(f"{USERS_PATH}/{user_id}")

    assert response.status_code == status.HTTP_422_UNPROCESSABLE_CONTENT
