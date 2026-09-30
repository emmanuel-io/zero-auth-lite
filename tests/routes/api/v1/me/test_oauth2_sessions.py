"""Black-box tests for `/api/v1/me/oauth2/sessions` self-service."""

from datetime import datetime, timedelta, UTC

import httpx
import pytest
from app.api.schemas import DEFAULT_PAGE_LIMIT_MAX
from app.db.models.oauth2_session import OAuth2SessionDB
from app.db.models.oauth2_token_state import OAuth2TokenStateDB
from app.db.models.organization_membership import OrganizationMembershipDB
from app.db.models.user import UserDB, UserEmailDB
from app.identity.users.enums import OrganizationMembershipRole, UserEmailStatus
from fastapi import FastAPI, status
from sqlalchemy import select, update

from tests.fixtures.auth import (
    current_user_id_for_email,
    issue_user_token,
    pre_session_csrf_headers,
    UserCredentials,
)
from tests.fixtures.oauth2 import add_oauth2_required_context_route
from tests.identifiers import (
    deterministic_uuid,
    format_public_id as format_oauth2_session_id,
    parse_public_id as parse_oauth2_session_id,
    UUID4_VERSION,
)


pytestmark = pytest.mark.api
OAUTH2_SESSIONS_PATH = "/api/v1/me/oauth2/sessions"
PAGINATED_SESSION_COUNT = 2


@pytest.mark.asyncio
@pytest.mark.negative
async def test_revoke_foreign_or_unknown_oauth2_session_returns_not_found(
    app: FastAPI,
    client: httpx.AsyncClient,
    verified_user_credentials: UserCredentials,
) -> None:
    """Do not reveal whether an OAuth2 session belongs to another user."""
    token_response = await issue_user_token(app, client, verified_user_credentials)
    assert token_response.status_code == status.HTTP_200_OK
    session_payload = (await client.get(OAUTH2_SESSIONS_PATH)).json()["items"][0]

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
                    role=OrganizationMembershipRole.MEMBER,
                ),
            ]
        )
        public_id = parse_oauth2_session_id(session_payload["id"])
        oauth2_session = await db_session.scalar(
            select(OAuth2SessionDB).where(OAuth2SessionDB.public_id == public_id)
        )
        assert oauth2_session is not None
        oauth2_session.user_id = foreign_user.id
        await db_session.commit()

    headers = await pre_session_csrf_headers(client)
    foreign_response = await client.delete(
        f"{OAUTH2_SESSIONS_PATH}/{session_payload['id']}",
        headers=headers,
    )
    unknown_response = await client.delete(
        f"{OAUTH2_SESSIONS_PATH}/00000000-0000-4000-8000-000000000000",
        headers=headers,
    )

    assert foreign_response.status_code == status.HTTP_404_NOT_FOUND
    assert foreign_response.json()["code"] == "OAUTH2_SESSION_NOT_FOUND"
    assert unknown_response.status_code == status.HTTP_404_NOT_FOUND
    assert unknown_response.json()["code"] == "OAUTH2_SESSION_NOT_FOUND"


@pytest.mark.asyncio
@pytest.mark.negative
async def test_revoke_already_ended_oauth2_session_returns_not_found(
    app: FastAPI,
    client: httpx.AsyncClient,
    verified_user_credentials: UserCredentials,
) -> None:
    """Reject an OAuth2 session that is no longer active."""
    token_response = await issue_user_token(app, client, verified_user_credentials)
    assert token_response.status_code == status.HTTP_200_OK
    session_payload = (await client.get(OAUTH2_SESSIONS_PATH)).json()["items"][0]

    async with app.state.core_session_factory() as db_session:
        public_id = parse_oauth2_session_id(session_payload["id"])
        oauth2_session = await db_session.scalar(
            select(OAuth2SessionDB).where(OAuth2SessionDB.public_id == public_id)
        )
        assert oauth2_session is not None
        oauth2_session.ended_at = datetime.now(UTC)
        await db_session.commit()

    headers = await pre_session_csrf_headers(client)
    response = await client.delete(
        f"{OAUTH2_SESSIONS_PATH}/{session_payload['id']}",
        headers=headers,
    )

    assert response.status_code == status.HTTP_404_NOT_FOUND
    assert response.json()["code"] == "OAUTH2_SESSION_NOT_FOUND"


@pytest.mark.asyncio
async def test_user_can_list_oauth2_sessions(
    app: FastAPI,
    client: httpx.AsyncClient,
    verified_user_credentials: UserCredentials,
) -> None:
    """Expose grant and client metadata without exposing token-pair details."""
    token_response = await issue_user_token(app, client, verified_user_credentials)
    assert token_response.status_code == status.HTTP_200_OK

    response = await client.get(OAUTH2_SESSIONS_PATH)

    assert response.status_code == status.HTTP_200_OK
    assert response.headers["Cache-Control"] == "no-store"
    payload = response.json()
    assert payload["offset"] == 0
    assert payload["limit"] == DEFAULT_PAGE_LIMIT_MAX
    assert payload["total"] == 1
    assert len(payload["items"]) == 1
    oauth2_session = payload["items"][0]
    assert parse_oauth2_session_id(oauth2_session["id"]).version == UUID4_VERSION
    assert oauth2_session["client_id"] == str(deterministic_uuid("test-user-client"))
    assert oauth2_session["client_name"] == "Test User Client"
    assert oauth2_session["scopes"] == ["read"]
    assert oauth2_session["created_at"]
    assert oauth2_session["last_token_issued_at"]
    assert "last_used_at" not in oauth2_session
    assert "access_token" not in oauth2_session
    assert "refresh_token" not in oauth2_session
    assert "access_expires_at" not in oauth2_session
    organization_sessions = await client.get("/api/v1/organization/oauth2/sessions")
    assert organization_sessions.status_code == status.HTTP_200_OK
    organization_session = organization_sessions.json()["items"][0]
    assert organization_session["id"] == oauth2_session["id"]
    assert organization_session["scopes"] == oauth2_session["scopes"]


@pytest.mark.asyncio
async def test_user_oauth2_sessions_are_ordered_by_session_creation(
    app: FastAPI,
    client: httpx.AsyncClient,
    verified_user_credentials: UserCredentials,
) -> None:
    """Order sessions by creation even when token activity is newer elsewhere."""
    for _ in range(PAGINATED_SESSION_COUNT):
        response = await issue_user_token(app, client, verified_user_credentials)
        assert response.status_code == status.HTTP_200_OK

    now = datetime.now(UTC)
    async with app.state.core_session_factory() as db_session:
        sessions = list(
            (
                await db_session.scalars(
                    select(OAuth2SessionDB).order_by(OAuth2SessionDB.id)
                )
            ).all()
        )
        assert len(sessions) == PAGINATED_SESSION_COUNT
        newest_session, older_session = sessions
        expected_ids = [
            format_oauth2_session_id(newest_session.public_id),
            format_oauth2_session_id(older_session.public_id),
        ]
        newest_session.created_at = now - timedelta(hours=1)
        older_session.created_at = now - timedelta(hours=2)
        await db_session.execute(
            update(OAuth2TokenStateDB)
            .where(OAuth2TokenStateDB.session_id == newest_session.id)
            .values(updated_at=now - timedelta(days=2))
        )
        await db_session.execute(
            update(OAuth2TokenStateDB)
            .where(OAuth2TokenStateDB.session_id == older_session.id)
            .values(updated_at=now)
        )
        await db_session.commit()

    response = await client.get(OAUTH2_SESSIONS_PATH)
    items = response.json()["items"]

    assert response.status_code == status.HTTP_200_OK
    assert [item["id"] for item in items] == expected_ids
    first_token_issued_at = datetime.fromisoformat(items[0]["last_token_issued_at"])
    second_token_issued_at = datetime.fromisoformat(items[1]["last_token_issued_at"])
    assert first_token_issued_at < second_token_issued_at


@pytest.mark.asyncio
async def test_user_oauth2_session_listing_excludes_expired_token_families(
    app: FastAPI,
    client: httpx.AsyncClient,
    verified_user_credentials: UserCredentials,
) -> None:
    """Hide grants after their effective token-family expiry."""
    token_response = await issue_user_token(app, client, verified_user_credentials)
    assert token_response.status_code == status.HTTP_200_OK
    async with app.state.core_session_factory() as db_session:
        await db_session.execute(
            update(OAuth2TokenStateDB).values(
                access_expires_at=datetime.now(UTC),
                refresh_expires_at=datetime.now(UTC),
            )
        )
        await db_session.commit()

    response = await client.get(OAUTH2_SESSIONS_PATH)

    assert response.status_code == status.HTTP_200_OK
    assert response.json() == {"items": [], "offset": 0, "limit": 100, "total": 0}


@pytest.mark.asyncio
async def test_session_surfaces_share_current_token_family_filtering(
    app: FastAPI,
    client: httpx.AsyncClient,
    verified_user_credentials: UserCredentials,
) -> None:
    """Apply the same access-only and ended-session rules on both list routes."""
    token_response = await issue_user_token(app, client, verified_user_credentials)
    assert token_response.status_code == status.HTTP_200_OK
    async with app.state.core_session_factory() as db_session:
        await db_session.execute(
            update(OAuth2TokenStateDB).values(
                refresh_token_hash=None,
                refresh_expires_at=None,
                access_expires_at=datetime.now(UTC) + timedelta(minutes=1),
            )
        )
        await db_session.commit()

    user_response = await client.get(OAUTH2_SESSIONS_PATH)
    organization_response = await client.get("/api/v1/organization/oauth2/sessions")

    assert user_response.json()["total"] == 1
    assert organization_response.json()["total"] == 1

    async with app.state.core_session_factory() as db_session:
        await db_session.execute(
            update(OAuth2SessionDB).values(ended_at=datetime.now(UTC))
        )
        await db_session.commit()

    user_response = await client.get(OAUTH2_SESSIONS_PATH)
    organization_response = await client.get("/api/v1/organization/oauth2/sessions")

    assert user_response.json()["total"] == 0
    assert organization_response.json()["total"] == 0


@pytest.mark.asyncio
async def test_user_can_page_through_oauth2_sessions(
    app: FastAPI,
    client: httpx.AsyncClient,
    verified_user_credentials: UserCredentials,
) -> None:
    """Expose every grant through stable offset pagination."""
    for _ in range(PAGINATED_SESSION_COUNT):
        token_response = await issue_user_token(app, client, verified_user_credentials)
        assert token_response.status_code == status.HTTP_200_OK

    first = await client.get(OAUTH2_SESSIONS_PATH, params={"offset": 0, "limit": 1})
    second = await client.get(OAUTH2_SESSIONS_PATH, params={"offset": 1, "limit": 1})

    assert first.status_code == status.HTTP_200_OK
    assert second.status_code == status.HTTP_200_OK
    assert first.json()["total"] == second.json()["total"] == PAGINATED_SESSION_COUNT
    assert first.json()["offset"] == 0
    assert second.json()["offset"] == 1
    assert first.json()["items"][0]["id"] != second.json()["items"][0]["id"]


@pytest.mark.asyncio
@pytest.mark.system
async def test_user_can_revoke_owned_oauth2_session(
    app: FastAPI,
    client: httpx.AsyncClient,
    verified_user_credentials: UserCredentials,
) -> None:
    """End the grant session and invalidate its associated bearer state."""
    add_oauth2_required_context_route(app)
    token_response = await issue_user_token(app, client, verified_user_credentials)
    assert token_response.status_code == status.HTTP_200_OK
    access_token = token_response.json()["access_token"]
    oauth2_session = (await client.get(OAUTH2_SESSIONS_PATH)).json()["items"][0]
    assert (
        await client.get(
            "/test/oauth2/required-context",
            headers={"Authorization": f"Bearer {access_token}"},
        )
    ).status_code == status.HTTP_200_OK
    headers = await pre_session_csrf_headers(client)

    response = await client.delete(
        f"{OAUTH2_SESSIONS_PATH}/{oauth2_session['id']}",
        headers=headers,
    )

    assert response.status_code == status.HTTP_204_NO_CONTENT
    assert response.content == b""
    assert (await client.get(OAUTH2_SESSIONS_PATH)).json()["items"] == []
    assert (
        await client.get(
            "/test/oauth2/required-context",
            headers={"Authorization": f"Bearer {access_token}"},
        )
    ).status_code == status.HTTP_401_UNAUTHORIZED


@pytest.mark.asyncio
@pytest.mark.negative
async def test_oauth2_sessions_require_browser_authentication(
    client: httpx.AsyncClient,
) -> None:
    """Prevent anonymous callers from inspecting or revoking grants."""
    assert (
        await client.get(OAUTH2_SESSIONS_PATH)
    ).status_code == status.HTTP_401_UNAUTHORIZED
    assert (
        await client.delete(
            f"{OAUTH2_SESSIONS_PATH}/00000000-0000-4000-8000-000000000000"
        )
    ).status_code == status.HTTP_401_UNAUTHORIZED
