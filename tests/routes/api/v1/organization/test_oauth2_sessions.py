"""Black-box tests for current-organization OAuth2 session administration."""

from datetime import datetime, timedelta, UTC

import httpx
import pytest
from app.api.schemas import DEFAULT_PAGE_LIMIT_MAX
from app.db.models.oauth2_session import OAuth2SessionDB
from app.db.models.oauth2_token_state import OAuth2TokenStateDB
from app.db.models.organization import OrganizationDB
from app.db.models.organization_membership import OrganizationMembershipDB
from app.db.models.user import UserDB
from app.identity.users.enums import OrganizationMembershipRole
from fastapi import FastAPI, status
from sqlalchemy import func, select, update

from tests.fixtures.auth import (
    current_user_id_for_email,
    issue_user_token,
    pre_session_csrf_headers,
    UserCredentials,
)
from tests.identifiers import (
    deterministic_uuid,
    format_public_id as format_oauth2_session_id,
    parse_public_id as parse_oauth2_session_id,
    UUID4_VERSION,
)
from tests.routes.api.helpers import login_headers


pytestmark = pytest.mark.api
ORGANIZATION_OAUTH2_PATH = "/api/v1/organization/oauth2"
PAGINATED_SESSION_COUNT = 2


@pytest.mark.asyncio
@pytest.mark.system
async def test_organization_admin_can_inspect_and_revoke_oauth2_sessions(
    app: FastAPI,
    client: httpx.AsyncClient,
    verified_user_credentials: UserCredentials,
) -> None:
    """Expose issued token families and revoke them inside the current organization."""
    token_response = await issue_user_token(app, client, verified_user_credentials)
    assert token_response.status_code == status.HTTP_200_OK

    sessions_response = await client.get(f"{ORGANIZATION_OAUTH2_PATH}/sessions")

    assert sessions_response.status_code == status.HTTP_200_OK
    assert sessions_response.headers["Cache-Control"] == "no-store"
    payload = sessions_response.json()
    assert payload["offset"] == 0
    assert payload["limit"] == DEFAULT_PAGE_LIMIT_MAX
    assert payload["total"] == 1
    sessions = payload["items"]
    assert len(sessions) == 1
    assert sessions[0]["client_id"] == str(deterministic_uuid("test-user-client"))
    assert parse_oauth2_session_id(sessions[0]["id"]).version == UUID4_VERSION
    assert sessions[0]["scopes"] == ["read"]
    assert "session_id" not in sessions[0]
    assert "scope" not in sessions[0]
    assert sessions[0]["active"] is True
    assert "session_ended_at" not in sessions[0]

    headers = await pre_session_csrf_headers(client)
    revoke_response = await client.delete(
        f"{ORGANIZATION_OAUTH2_PATH}/sessions/{sessions[0]['id']}",
        headers=headers,
    )

    assert revoke_response.status_code == status.HTTP_200_OK
    assert revoke_response.json() == {
        "revoked_sessions": 1,
        "revoked_token_states": 1,
    }
    assert (
        await client.get(
            f"{ORGANIZATION_OAUTH2_PATH}/sessions",
            params={"active_only": False},
        )
    ).json()["items"] == []


@pytest.mark.asyncio
@pytest.mark.system
async def test_organization_admin_can_revoke_client_tokens(
    app: FastAPI,
    client: httpx.AsyncClient,
    verified_user_credentials: UserCredentials,
) -> None:
    """Revoke every token family for one client in the current organization."""
    token_response = await issue_user_token(app, client, verified_user_credentials)
    assert token_response.status_code == status.HTTP_200_OK
    headers = await pre_session_csrf_headers(client)

    response = await client.delete(
        f"{ORGANIZATION_OAUTH2_PATH}/clients/{deterministic_uuid('test-user-client')}/tokens",
        headers=headers,
    )

    assert response.status_code == status.HTTP_200_OK
    assert response.json() == {
        "revoked_sessions": 1,
        "revoked_token_states": 1,
    }


@pytest.mark.asyncio
@pytest.mark.negative
async def test_session_filter_rejects_refresh_token_grant(
    app: FastAPI,
    client: httpx.AsyncClient,
    verified_user_credentials: UserCredentials,
) -> None:
    """Accept only grants that can originate a persisted OAuth2 session."""
    await issue_user_token(app, client, verified_user_credentials)

    response = await client.get(
        f"{ORGANIZATION_OAUTH2_PATH}/sessions",
        params={"grant_type": "refresh_token"},
    )

    assert response.status_code == status.HTTP_422_UNPROCESSABLE_CONTENT


@pytest.mark.asyncio
@pytest.mark.system
async def test_session_revocation_reports_actual_mutation_counts(
    app: FastAPI,
    client: httpx.AsyncClient,
    verified_user_credentials: UserCredentials,
) -> None:
    """Report a residual token deletion without claiming to end a session twice."""
    token_response = await issue_user_token(app, client, verified_user_credentials)
    assert token_response.status_code == status.HTTP_200_OK
    async with app.state.core_session_factory() as db_session:
        session_id = await db_session.scalar(
            select(OAuth2SessionDB.id).where(
                OAuth2SessionDB.client_id == deterministic_uuid("test-user-client")
            )
        )
        assert session_id is not None
        await db_session.execute(
            update(OAuth2SessionDB)
            .where(OAuth2SessionDB.id == session_id)
            .values(ended_at=datetime.now(UTC))
        )
        await db_session.commit()
    sessions = await client.get(
        f"{ORGANIZATION_OAUTH2_PATH}/sessions",
        params={"active_only": False},
    )
    session_public_id = sessions.json()["items"][0]["id"]
    headers = await pre_session_csrf_headers(client)

    response = await client.delete(
        f"{ORGANIZATION_OAUTH2_PATH}/sessions/{session_public_id}",
        headers=headers,
    )

    assert response.status_code == status.HTTP_200_OK
    assert response.json() == {
        "revoked_sessions": 0,
        "revoked_token_states": 1,
    }


@pytest.mark.asyncio
@pytest.mark.system
async def test_organization_oauth2_session_listing_excludes_expired_token_families(
    app: FastAPI,
    client: httpx.AsyncClient,
    verified_user_credentials: UserCredentials,
) -> None:
    """Apply active filtering before limiting and mapping session responses."""
    token_response = await issue_user_token(app, client, verified_user_credentials)
    assert token_response.status_code == status.HTTP_200_OK
    async with app.state.core_session_factory() as db_session:
        session_id = await db_session.scalar(
            select(OAuth2SessionDB.id).where(
                OAuth2SessionDB.client_id == deterministic_uuid("test-user-client")
            )
        )
        assert session_id is not None
        await db_session.execute(
            update(OAuth2TokenStateDB)
            .where(OAuth2TokenStateDB.session_id == session_id)
            .values(
                access_expires_at=datetime.now(UTC) - timedelta(minutes=1),
                refresh_expires_at=datetime.now(UTC) - timedelta(minutes=1),
            )
        )
        await db_session.commit()

    active_response = await client.get(f"{ORGANIZATION_OAUTH2_PATH}/sessions")
    all_response = await client.get(
        f"{ORGANIZATION_OAUTH2_PATH}/sessions",
        params={"active_only": False},
    )

    assert active_response.status_code == status.HTTP_200_OK
    assert active_response.json()["items"] == []
    assert active_response.json()["total"] == 0
    assert all_response.status_code == status.HTTP_200_OK
    assert len(all_response.json()["items"]) == 1
    assert all_response.json()["total"] == 1
    assert all_response.json()["items"][0]["active"] is False


@pytest.mark.asyncio
@pytest.mark.system
async def test_organization_admin_can_page_through_oauth2_sessions(
    app: FastAPI,
    client: httpx.AsyncClient,
    verified_user_credentials: UserCredentials,
) -> None:
    """Expose every matching token family through stable offset pagination."""
    for _ in range(PAGINATED_SESSION_COUNT):
        token_response = await issue_user_token(app, client, verified_user_credentials)
        assert token_response.status_code == status.HTTP_200_OK

    first = await client.get(
        f"{ORGANIZATION_OAUTH2_PATH}/sessions",
        params={"offset": 0, "limit": 1},
    )
    second = await client.get(
        f"{ORGANIZATION_OAUTH2_PATH}/sessions",
        params={"offset": 1, "limit": 1},
    )

    assert first.status_code == status.HTTP_200_OK
    assert second.status_code == status.HTTP_200_OK
    assert first.json()["total"] == second.json()["total"] == PAGINATED_SESSION_COUNT
    assert first.json()["items"][0]["id"] != second.json()["items"][0]["id"]


@pytest.mark.asyncio
@pytest.mark.system
async def test_organization_oauth2_sessions_are_ordered_by_session_creation(
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

    response = await client.get(f"{ORGANIZATION_OAUTH2_PATH}/sessions")
    items = response.json()["items"]

    assert response.status_code == status.HTTP_200_OK
    assert [item["id"] for item in items] == expected_ids
    first_token_updated_at = datetime.fromisoformat(items[0]["updated_at"])
    second_token_updated_at = datetime.fromisoformat(items[1]["updated_at"])
    assert first_token_updated_at < second_token_updated_at


@pytest.mark.asyncio
@pytest.mark.system
async def test_client_revocation_does_not_touch_another_organizations_tokens(
    app: FastAPI,
    client: httpx.AsyncClient,
    verified_user_credentials: UserCredentials,
) -> None:
    """Return zero without revealing client tokens owned by another organization."""
    token_response = await issue_user_token(app, client, verified_user_credentials)
    assert token_response.status_code == status.HTTP_200_OK
    async with app.state.core_session_factory() as db_session:
        other_organization = OrganizationDB(name="Other Organization")
        db_session.add(other_organization)
        await db_session.flush()
        await db_session.execute(
            update(OAuth2SessionDB)
            .where(OAuth2SessionDB.client_id == deterministic_uuid("test-user-client"))
            .values(organization_id=other_organization.id)
        )
        await db_session.commit()
    headers = await pre_session_csrf_headers(client)

    response = await client.delete(
        f"{ORGANIZATION_OAUTH2_PATH}/clients/{deterministic_uuid('test-user-client')}/tokens",
        headers=headers,
    )

    assert response.status_code == status.HTTP_200_OK
    assert response.json() == {"revoked_sessions": 0, "revoked_token_states": 0}
    async with app.state.core_session_factory() as db_session:
        remaining = await db_session.scalar(
            select(func.count())
            .select_from(OAuth2TokenStateDB)
            .join(OAuth2SessionDB, OAuth2SessionDB.id == OAuth2TokenStateDB.session_id)
            .where(OAuth2SessionDB.client_id == deterministic_uuid("test-user-client"))
        )
    assert remaining == 1


@pytest.mark.asyncio
@pytest.mark.negative
async def test_oauth2_operations_require_authentication(
    client: httpx.AsyncClient,
) -> None:
    """Prevent anonymous callers from inspecting or revoking organization sessions."""
    assert (
        await client.get(f"{ORGANIZATION_OAUTH2_PATH}/sessions")
    ).status_code == status.HTTP_401_UNAUTHORIZED
    assert (
        await client.delete(
            f"{ORGANIZATION_OAUTH2_PATH}/sessions/00000000-0000-4000-8000-000000000000"
        )
    ).status_code == status.HTTP_401_UNAUTHORIZED


@pytest.mark.asyncio
@pytest.mark.negative
async def test_oauth2_operations_require_explicit_organization_admin_role(
    app: FastAPI,
    client: httpx.AsyncClient,
    verified_user_credentials: UserCredentials,
) -> None:
    """Reject a server operator that is not an organization administrator."""
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
            .values(role=OrganizationMembershipRole.MEMBER)
        )
        await db_session.execute(
            update(UserDB)
            .where(
                UserDB.id == current_user_id_for_email(verified_user_credentials.email)
            )
            .values(is_operator=True)
        )
        await db_session.commit()
    await login_headers(client, verified_user_credentials)

    response = await client.get(f"{ORGANIZATION_OAUTH2_PATH}/sessions")

    assert response.status_code == status.HTTP_403_FORBIDDEN
    assert response.json()["code"] == "FORBIDDEN_OPERATION"


@pytest.mark.asyncio
@pytest.mark.negative
async def test_oauth2_operations_require_matching_oauth2_scope(
    app: FastAPI,
    client: httpx.AsyncClient,
    verified_user_credentials: UserCredentials,
) -> None:
    """Reject an OAuth2 user token that lacks the route permission scope."""
    token_response = await issue_user_token(app, client, verified_user_credentials)
    assert token_response.status_code == status.HTTP_200_OK

    response = await client.get(
        f"{ORGANIZATION_OAUTH2_PATH}/sessions",
        headers={"Authorization": f"Bearer {token_response.json()['access_token']}"},
    )

    assert response.status_code == status.HTTP_403_FORBIDDEN


@pytest.mark.asyncio
@pytest.mark.negative
async def test_oauth2_operation_write_requires_csrf(
    client: httpx.AsyncClient,
    verified_user_credentials: UserCredentials,
) -> None:
    """Reject browser-session token revocation without CSRF proof."""
    await login_headers(client, verified_user_credentials)

    response = await client.delete(
        f"{ORGANIZATION_OAUTH2_PATH}/clients/missing-client/tokens"
    )

    assert response.status_code == status.HTTP_403_FORBIDDEN


@pytest.mark.asyncio
@pytest.mark.negative
async def test_oauth2_operations_translate_missing_session_and_hide_client_existence(
    client: httpx.AsyncClient,
    verified_user_credentials: UserCredentials,
) -> None:
    """Keep session lookup explicit while making client revocation idempotent."""
    headers = await login_headers(client, verified_user_credentials)

    missing_session = await client.delete(
        f"{ORGANIZATION_OAUTH2_PATH}/sessions/00000000-0000-4000-8000-000000000000",
        headers=headers,
    )
    missing_client = await client.delete(
        f"{ORGANIZATION_OAUTH2_PATH}/clients/{deterministic_uuid('missing-client')}/tokens",
        headers=headers,
    )
    repeated_client = await client.delete(
        f"{ORGANIZATION_OAUTH2_PATH}/clients/{deterministic_uuid('missing-client')}/tokens",
        headers=headers,
    )

    assert missing_session.status_code == status.HTTP_404_NOT_FOUND
    assert missing_session.json()["code"] == "OAUTH2_SESSION_NOT_FOUND"
    assert missing_client.status_code == status.HTTP_200_OK
    assert missing_client.json() == {
        "revoked_sessions": 0,
        "revoked_token_states": 0,
    }
    assert repeated_client.status_code == status.HTTP_200_OK
    assert repeated_client.json() == missing_client.json()
