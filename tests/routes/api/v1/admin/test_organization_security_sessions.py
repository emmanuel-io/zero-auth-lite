"""Black-box tests for explicit-organization security-session revocation."""

import base64
from datetime import datetime, timedelta, UTC

import httpx
import pytest
from app.db.models.browser_session import BrowserSessionDB
from app.db.models.oauth2_client import (
    OAuth2ClientDB,
    OAuth2ClientMachineOrganizationDB,
)
from app.db.models.oauth2_session import OAuth2SessionDB
from app.db.models.oauth2_token_pair import OAuth2TokenPairDB
from app.db.models.organization import OrganizationDB
from app.db.models.organization_membership import OrganizationMembershipDB
from app.db.models.user import UserDB, UserEmailDB
from app.identity.public_ids import format_organization_id
from app.identity.users.enums import OrganizationUserRole, UserEmailStatus
from app.password.pwdlib_hasher import PwdlibPasswordHasher
from app.public_ids import PublicId
from fastapi import FastAPI, status
from sqlalchemy import select, update

from tests.fixtures.auth import (
    current_user_id_for_email,
    issue_user_token,
    UserCredentials,
)
from tests.routes.api.helpers import login_headers


pytestmark = pytest.mark.api
PASSWORD_HASHER = PwdlibPasswordHasher()
MACHINE_SECRET = "organization-revoker-secret"  # noqa: S105


async def seed_machine_and_organizations(
    app: FastAPI,
    credentials: UserCredentials,
    *,
    mode: str = "single",
) -> tuple[str, int, str, int]:
    """Create an assigned machine client and a second isolated organization."""
    async with app.state.core_session_factory() as db_session:
        target_user = await db_session.scalar(
            select(UserDB).where(
                UserDB.id == current_user_id_for_email(credentials.email)
            )
        )
        assert target_user is not None
        target_membership = await db_session.get(
            OrganizationMembershipDB, target_user.id
        )
        assert target_membership is not None
        target_organization = await db_session.get(
            OrganizationDB, target_membership.organization_id
        )
        assert target_organization is not None

        other_organization = OrganizationDB(name="Other Organization")
        db_session.add(other_organization)
        await db_session.flush()
        other_user = UserDB(
            hashed_password=PASSWORD_HASHER.hash("OtherSecret1!"),
            is_active=True,
        )
        machine = OAuth2ClientDB(
            client_id="organization-session-revoker",
            client_secret=PASSWORD_HASHER.hash(MACHINE_SECRET),
            name="Organization Session Revoker",
            grant_types=["client_credentials"],
            scopes=["users:write", "organization:read"],
            redirect_uris=[],
            is_confidential=True,
            is_active=True,
            machine_organization_access=mode,
        )
        db_session.add_all([other_user, machine])
        await db_session.flush()
        db_session.add(
            UserEmailDB(
                user_id=other_user.id,
                email="other-organization-user@example.com",
                normalized_email="other-organization-user@example.com",
                status=UserEmailStatus.CURRENT,
                verified_at=datetime.now(UTC),
            )
        )
        db_session.add(
            OrganizationMembershipDB(
                user_id=other_user.id,
                organization_id=other_organization.id,
                role=OrganizationUserRole.MEMBER,
            )
        )
        if mode in {"single", "selected"}:
            db_session.add(
                OAuth2ClientMachineOrganizationDB(
                    client_id=machine.id,
                    organization_id=target_organization.id,
                )
            )
        await db_session.commit()
        return (
            format_organization_id(target_organization.public_id),
            target_user.id,
            format_organization_id(other_organization.public_id),
            other_user.id,
        )


async def issue_machine_token(
    client: httpx.AsyncClient, *, scope: str = "users:write"
) -> str:
    """Issue a real client-credentials access token for the seeded machine."""
    basic = base64.b64encode(
        f"organization-session-revoker:{MACHINE_SECRET}".encode()
    ).decode()
    response = await client.post(
        "/oauth2/token",
        data={"grant_type": "client_credentials", "scope": scope},
        headers={"Authorization": f"Basic {basic}"},
    )
    assert response.status_code == status.HTTP_200_OK
    return response.json()["access_token"]


async def seed_organization_sessions(
    app: FastAPI,
    *,
    target_user_id: int,
    other_user_id: int,
) -> tuple[int, int]:
    """Persist browser and OAuth2 sessions in two organizations."""
    now = datetime.now(UTC)
    async with app.state.core_session_factory() as db_session:
        db_session.add_all(
            [
                BrowserSessionDB(
                    id="target-browser-session",
                    user_id=target_user_id,
                    csrf="target-csrf",
                    absolute_expires_at=now + timedelta(hours=8),
                    expires_at=now + timedelta(hours=1),
                    last_seen_at=now,
                ),
                BrowserSessionDB(
                    id="other-browser-session",
                    user_id=other_user_id,
                    csrf="other-csrf",
                    absolute_expires_at=now + timedelta(hours=8),
                    expires_at=now + timedelta(hours=1),
                    last_seen_at=now,
                ),
            ]
        )
        target_membership = await db_session.get(
            OrganizationMembershipDB, target_user_id
        )
        other_membership = await db_session.get(OrganizationMembershipDB, other_user_id)
        assert target_membership is not None
        assert other_membership is not None
        target_oauth2 = OAuth2SessionDB(
            client_id="organization-session-revoker",
            grant_type="authorization_code",
            scope="users:write",
            user_id=target_user_id,
            organization_id=target_membership.organization_id,
        )
        other_oauth2 = OAuth2SessionDB(
            client_id="organization-session-revoker",
            grant_type="authorization_code",
            scope="users:write",
            user_id=other_user_id,
            organization_id=other_membership.organization_id,
        )
        db_session.add_all([target_oauth2, other_oauth2])
        await db_session.flush()
        db_session.add_all(
            [
                OAuth2TokenPairDB(
                    session_id=target_oauth2.id,
                    access_token_hash="target-access-hash",  # noqa: S106
                    access_jti="target-access-jti",
                    refresh_token_hash="target-refresh-hash",  # noqa: S106
                    access_expires_at=now + timedelta(minutes=15),
                    refresh_expires_at=now + timedelta(days=1),
                ),
                OAuth2TokenPairDB(
                    session_id=other_oauth2.id,
                    access_token_hash="other-access-hash",  # noqa: S106
                    access_jti="other-access-jti",
                    refresh_token_hash="other-refresh-hash",  # noqa: S106
                    access_expires_at=now + timedelta(minutes=15),
                    refresh_expires_at=now + timedelta(days=1),
                ),
            ]
        )
        await db_session.commit()
        return target_oauth2.id, other_oauth2.id


@pytest.mark.asyncio
@pytest.mark.system
@pytest.mark.parametrize("mode", ["single", "selected"])
async def test_machine_revokes_only_assigned_organization_sessions(
    app: FastAPI,
    client: httpx.AsyncClient,
    verified_user_credentials: UserCredentials,
    mode: str,
) -> None:
    """Exercise real machine policy and atomic organization session revocation."""
    (
        target_organization_id,
        target_user_id,
        other_organization_id,
        other_user_id,
    ) = await seed_machine_and_organizations(app, verified_user_credentials, mode=mode)
    target_oauth2_id, other_oauth2_id = await seed_organization_sessions(
        app,
        target_user_id=target_user_id,
        other_user_id=other_user_id,
    )
    token = await issue_machine_token(client)

    denied = await client.delete(
        f"/api/v1/admin/organizations/{other_organization_id}/sessions",
        headers={"Authorization": f"Bearer {token}"},
    )
    missing = await client.delete(
        f"/api/v1/admin/organizations/{format_organization_id(PublicId(1))}/sessions",
        headers={"Authorization": f"Bearer {token}"},
    )
    response = await client.delete(
        f"/api/v1/admin/organizations/{target_organization_id}/sessions",
        headers={"Authorization": f"Bearer {token}"},
    )

    assert denied.status_code == status.HTTP_404_NOT_FOUND
    assert denied.json()["message"] == "The requested object was not found."
    assert missing.status_code == status.HTTP_404_NOT_FOUND
    assert missing.json() == denied.json()
    assert response.status_code == status.HTTP_204_NO_CONTENT
    assert response.content == b""

    async with app.state.core_session_factory() as db_session:
        target_browser = await db_session.get(
            BrowserSessionDB, "target-browser-session"
        )
        other_browser = await db_session.get(BrowserSessionDB, "other-browser-session")
        target_oauth2 = await db_session.get(OAuth2SessionDB, target_oauth2_id)
        other_oauth2 = await db_session.get(OAuth2SessionDB, other_oauth2_id)
        machine_pair = await db_session.scalar(
            select(OAuth2TokenPairDB)
            .join(OAuth2SessionDB, OAuth2SessionDB.id == OAuth2TokenPairDB.session_id)
            .where(OAuth2SessionDB.client_id == "organization-session-revoker")
        )
        assert target_browser is not None
        assert target_browser.revoked_at is not None
        assert target_browser.revoked_reason == "organization_sessions_revoked"
        assert other_browser is not None
        assert other_browser.revoked_at is None
        assert target_oauth2 is not None
        assert target_oauth2.ended_at is not None
        assert other_oauth2 is not None
        assert other_oauth2.ended_at is None
        assert await db_session.get(OAuth2TokenPairDB, target_oauth2_id) is None
        assert await db_session.get(OAuth2TokenPairDB, other_oauth2_id) is not None
        assert machine_pair is not None


@pytest.mark.asyncio
@pytest.mark.negative
async def test_organization_session_revocation_rejects_none_and_inactive_clients(
    app: FastAPI,
    client: httpx.AsyncClient,
    verified_user_credentials: UserCredentials,
) -> None:
    """Reject disabled machine policy and client lifecycle state."""
    (
        target_organization_id,
        _target_user_id,
        _other_organization_id,
        _other_user_id,
    ) = await seed_machine_and_organizations(
        app,
        verified_user_credentials,
        mode="none",
    )
    token = await issue_machine_token(client)
    denied = await client.delete(
        f"/api/v1/admin/organizations/{target_organization_id}/sessions",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert denied.status_code == status.HTTP_403_FORBIDDEN

    async with app.state.core_session_factory() as db_session:
        await db_session.execute(
            update(OAuth2ClientDB)
            .where(OAuth2ClientDB.client_id == "organization-session-revoker")
            .values(is_active=False)
        )
        await db_session.commit()
    inactive = await client.delete(
        f"/api/v1/admin/organizations/{target_organization_id}/sessions",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert inactive.status_code == status.HTTP_401_UNAUTHORIZED


@pytest.mark.asyncio
@pytest.mark.negative
async def test_organization_session_revocation_requires_valid_authentication(
    app: FastAPI,
    client: httpx.AsyncClient,
    verified_user_credentials: UserCredentials,
) -> None:
    """Return the normal API authentication error for absent or bad bearers."""
    target_organization_id, *_ = await seed_machine_and_organizations(
        app, verified_user_credentials
    )
    missing = await client.delete(
        f"/api/v1/admin/organizations/{target_organization_id}/sessions"
    )
    invalid = await client.delete(
        f"/api/v1/admin/organizations/{target_organization_id}/sessions",
        headers={"Authorization": "Bearer invalid"},
    )
    assert missing.status_code == status.HTTP_401_UNAUTHORIZED
    assert missing.json() == {
        "code": "UNAUTHORIZED",
        "message": "Unauthorized operation.",
        "details": [],
    }
    assert invalid.status_code == status.HTTP_401_UNAUTHORIZED
    assert invalid.json() == {
        "code": "UNAUTHORIZED",
        "message": "Unauthorized operation.",
        "details": [],
    }


@pytest.mark.asyncio
@pytest.mark.negative
async def test_machine_organization_session_revocation_requires_users_write_scope(
    app: FastAPI,
    client: httpx.AsyncClient,
    verified_user_credentials: UserCredentials,
) -> None:
    """Return 403 before organization lookup when the machine scope is insufficient."""
    target_organization_id, *_ = await seed_machine_and_organizations(
        app, verified_user_credentials
    )
    token = await issue_machine_token(client, scope="organization:read")

    response = await client.delete(
        f"/api/v1/admin/organizations/{target_organization_id}/sessions",
        headers={"Authorization": f"Bearer {token}"},
    )

    assert response.status_code == status.HTTP_403_FORBIDDEN


@pytest.mark.asyncio
async def test_operator_can_revoke_organization_sessions(
    app: FastAPI,
    client: httpx.AsyncClient,
    verified_user_credentials: UserCredentials,
) -> None:
    """Preserve existing cookie-authenticated operator behavior."""
    target_organization_id, *_ = await seed_machine_and_organizations(
        app, verified_user_credentials
    )
    headers = await login_headers(client, verified_user_credentials)
    response = await client.delete(
        f"/api/v1/admin/organizations/{target_organization_id}/sessions",
        headers=headers,
    )
    assert response.status_code == status.HTTP_204_NO_CONTENT
    assert any(
        cookie.startswith("sessionid=") and "Max-Age=0" in cookie
        for cookie in response.headers.get_list("set-cookie")
    )
    assert (await client.get("/api/v1/me")).status_code == status.HTTP_401_UNAUTHORIZED


@pytest.mark.asyncio
async def test_operator_bearer_can_revoke_organization_sessions(
    app: FastAPI,
    client: httpx.AsyncClient,
    verified_user_credentials: UserCredentials,
) -> None:
    """Preserve scoped OAuth2 bearer access for server operators."""
    target_organization_id, *_ = await seed_machine_and_organizations(
        app, verified_user_credentials
    )
    token_response = await issue_user_token(
        app,
        client,
        verified_user_credentials,
        scope="users:write",
    )
    assert token_response.status_code == status.HTTP_200_OK
    response = await client.delete(
        f"/api/v1/admin/organizations/{target_organization_id}/sessions",
        headers={"Authorization": f"Bearer {token_response.json()['access_token']}"},
    )
    assert response.status_code == status.HTTP_204_NO_CONTENT
    assert response.headers.get_list("set-cookie") == []
