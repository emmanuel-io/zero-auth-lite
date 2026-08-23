"""Black-box tests for `/api/v1/me/authorizations` administration."""

from datetime import datetime, UTC

import httpx
import pytest
from app.api.schemas import DEFAULT_PAGE_LIMIT_MAX
from app.db.models.oauth2_session import OAuth2SessionDB
from app.db.models.oauth2_token_pair import OAuth2TokenPairDB
from app.db.models.organization_membership import OrganizationMembershipDB
from app.db.models.user import UserDB, UserEmailDB
from app.identity.users.enums import OrganizationUserRole, UserEmailStatus
from app.oauth2.public_ids import parse_oauth2_session_id
from fastapi import FastAPI, status
from sqlalchemy import select, update

from tests.fixtures.auth import (
    current_user_id_for_email,
    issue_user_token,
    pre_session_csrf_headers,
    UserCredentials,
)
from tests.fixtures.oauth2 import add_oauth2_required_context_route


pytestmark = pytest.mark.api
AUTHORIZATIONS_PATH = "/api/v1/me/authorizations"
PAGINATED_AUTHORIZATION_COUNT = 2


@pytest.mark.asyncio
@pytest.mark.negative
async def test_revoke_foreign_or_unknown_authorization_returns_not_found(
    app: FastAPI,
    client: httpx.AsyncClient,
    verified_user_credentials: UserCredentials,
) -> None:
    """Do not reveal whether an authorization belongs to another user."""
    token_response = await issue_user_token(app, client, verified_user_credentials)
    assert token_response.status_code == status.HTTP_200_OK
    authorization = (await client.get(AUTHORIZATIONS_PATH)).json()["items"][0]

    async with app.state.core_session_factory() as db_session:
        current_user = await db_session.scalar(
            select(UserDB).where(
                UserDB.id == current_user_id_for_email(verified_user_credentials.email)
            )
        )
        assert current_user is not None
        current_membership = await db_session.get(
            OrganizationMembershipDB, current_user.id
        )
        assert current_membership is not None
        foreign_user = UserDB(
            first_name="Foreign",
            last_name="User",
            hashed_password=app.state.password_hasher.hash("F0reignSecret!"),
            is_active=True,
        )
        db_session.add(foreign_user)
        await db_session.flush()
        db_session.add_all(
            [
                UserEmailDB(
                    user_id=foreign_user.id,
                    email="foreign@example.com",
                    normalized_email="foreign@example.com",
                    status=UserEmailStatus.CURRENT,
                    verified_at=datetime.now(UTC),
                ),
                OrganizationMembershipDB(
                    user_id=foreign_user.id,
                    organization_id=current_membership.organization_id,
                    role=OrganizationUserRole.MEMBER,
                ),
            ]
        )
        public_id = parse_oauth2_session_id(authorization["id"])
        oauth2_session = await db_session.scalar(
            select(OAuth2SessionDB).where(OAuth2SessionDB.public_id == public_id)
        )
        assert oauth2_session is not None
        oauth2_session.user_id = foreign_user.id
        await db_session.commit()

    headers = await pre_session_csrf_headers(client)
    foreign_response = await client.delete(
        f"{AUTHORIZATIONS_PATH}/{authorization['id']}",
        headers=headers,
    )
    unknown_response = await client.delete(
        f"{AUTHORIZATIONS_PATH}/oas_0000000XSNJFZ",
        headers=headers,
    )

    assert foreign_response.status_code == status.HTTP_404_NOT_FOUND
    assert foreign_response.json()["code"] == "OAUTH2_AUTHORIZATION_NOT_FOUND"
    assert unknown_response.status_code == status.HTTP_404_NOT_FOUND
    assert unknown_response.json()["code"] == "OAUTH2_AUTHORIZATION_NOT_FOUND"


@pytest.mark.asyncio
@pytest.mark.negative
async def test_revoke_already_ended_authorization_returns_not_found(
    app: FastAPI,
    client: httpx.AsyncClient,
    verified_user_credentials: UserCredentials,
) -> None:
    """Reject an authorization whose OAuth2 session is no longer active."""
    token_response = await issue_user_token(app, client, verified_user_credentials)
    assert token_response.status_code == status.HTTP_200_OK
    authorization = (await client.get(AUTHORIZATIONS_PATH)).json()["items"][0]

    async with app.state.core_session_factory() as db_session:
        public_id = parse_oauth2_session_id(authorization["id"])
        oauth2_session = await db_session.scalar(
            select(OAuth2SessionDB).where(OAuth2SessionDB.public_id == public_id)
        )
        assert oauth2_session is not None
        oauth2_session.ended_at = datetime.now(UTC)
        await db_session.commit()

    headers = await pre_session_csrf_headers(client)
    response = await client.delete(
        f"{AUTHORIZATIONS_PATH}/{authorization['id']}",
        headers=headers,
    )

    assert response.status_code == status.HTTP_404_NOT_FOUND
    assert response.json()["code"] == "OAUTH2_AUTHORIZATION_NOT_FOUND"


@pytest.mark.asyncio
async def test_user_can_list_oauth2_authorizations(
    app: FastAPI,
    client: httpx.AsyncClient,
    verified_user_credentials: UserCredentials,
) -> None:
    """Expose grant and client metadata without exposing token-pair details."""
    token_response = await issue_user_token(app, client, verified_user_credentials)
    assert token_response.status_code == status.HTTP_200_OK

    response = await client.get(AUTHORIZATIONS_PATH)

    assert response.status_code == status.HTTP_200_OK
    assert response.headers["Cache-Control"] == "no-store"
    payload = response.json()
    assert payload["offset"] == 0
    assert payload["limit"] == DEFAULT_PAGE_LIMIT_MAX
    assert payload["total"] == 1
    assert len(payload["items"]) == 1
    authorization = payload["items"][0]
    assert authorization["id"].startswith("oas_")
    assert authorization["client_id"] == "test-user-client"
    assert authorization["client_name"] == "Test User Client"
    assert authorization["scopes"] == ["read"]
    assert authorization["created_at"]
    assert authorization["last_token_issued_at"]
    assert "last_used_at" not in authorization
    assert "access_token" not in authorization
    assert "refresh_token" not in authorization
    assert "access_expires_at" not in authorization
    organization_sessions = await client.get("/api/v1/organization/oauth2/sessions")
    assert organization_sessions.status_code == status.HTTP_200_OK
    assert organization_sessions.json()["items"][0]["session_id"] == authorization["id"]


@pytest.mark.asyncio
async def test_user_authorization_listing_excludes_expired_token_families(
    app: FastAPI,
    client: httpx.AsyncClient,
    verified_user_credentials: UserCredentials,
) -> None:
    """Hide grants after their effective token-family expiry."""
    token_response = await issue_user_token(app, client, verified_user_credentials)
    assert token_response.status_code == status.HTTP_200_OK
    async with app.state.core_session_factory() as db_session:
        await db_session.execute(
            update(OAuth2TokenPairDB).values(
                access_expires_at=datetime.now(UTC),
                refresh_expires_at=datetime.now(UTC),
            )
        )
        await db_session.commit()

    response = await client.get(AUTHORIZATIONS_PATH)

    assert response.status_code == status.HTTP_200_OK
    assert response.json() == {"items": [], "offset": 0, "limit": 100, "total": 0}


@pytest.mark.asyncio
async def test_user_can_page_through_oauth2_authorizations(
    app: FastAPI,
    client: httpx.AsyncClient,
    verified_user_credentials: UserCredentials,
) -> None:
    """Expose every grant through stable offset pagination."""
    for _ in range(PAGINATED_AUTHORIZATION_COUNT):
        token_response = await issue_user_token(app, client, verified_user_credentials)
        assert token_response.status_code == status.HTTP_200_OK

    first = await client.get(AUTHORIZATIONS_PATH, params={"offset": 0, "limit": 1})
    second = await client.get(AUTHORIZATIONS_PATH, params={"offset": 1, "limit": 1})

    assert first.status_code == status.HTTP_200_OK
    assert second.status_code == status.HTTP_200_OK
    assert (
        first.json()["total"] == second.json()["total"] == PAGINATED_AUTHORIZATION_COUNT
    )
    assert first.json()["offset"] == 0
    assert second.json()["offset"] == 1
    assert first.json()["items"][0]["id"] != second.json()["items"][0]["id"]


@pytest.mark.asyncio
@pytest.mark.system
async def test_user_can_revoke_owned_oauth2_authorization(
    app: FastAPI,
    client: httpx.AsyncClient,
    verified_user_credentials: UserCredentials,
) -> None:
    """End the grant session and invalidate its associated bearer state."""
    add_oauth2_required_context_route(app)
    token_response = await issue_user_token(app, client, verified_user_credentials)
    assert token_response.status_code == status.HTTP_200_OK
    access_token = token_response.json()["access_token"]
    authorization = (await client.get(AUTHORIZATIONS_PATH)).json()["items"][0]
    assert (
        await client.get(
            "/test/oauth2/required-context",
            headers={"Authorization": f"Bearer {access_token}"},
        )
    ).status_code == status.HTTP_200_OK
    headers = await pre_session_csrf_headers(client)

    response = await client.delete(
        f"{AUTHORIZATIONS_PATH}/{authorization['id']}",
        headers=headers,
    )

    assert response.status_code == status.HTTP_204_NO_CONTENT
    assert response.content == b""
    assert (await client.get(AUTHORIZATIONS_PATH)).json()["items"] == []
    assert (
        await client.get(
            "/test/oauth2/required-context",
            headers={"Authorization": f"Bearer {access_token}"},
        )
    ).status_code == status.HTTP_401_UNAUTHORIZED


@pytest.mark.asyncio
@pytest.mark.negative
async def test_authorizations_require_browser_authentication(
    client: httpx.AsyncClient,
) -> None:
    """Prevent anonymous callers from inspecting or revoking grants."""
    assert (
        await client.get(AUTHORIZATIONS_PATH)
    ).status_code == status.HTTP_401_UNAUTHORIZED
    assert (
        await client.delete(f"{AUTHORIZATIONS_PATH}/oas_0000000XSNJFZ")
    ).status_code == status.HTTP_401_UNAUTHORIZED
