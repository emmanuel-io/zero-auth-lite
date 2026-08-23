"""Black-box tests for current-organization OAuth2 session administration."""

from datetime import datetime, timedelta, UTC

import httpx
import pytest
from app.api.schemas import DEFAULT_PAGE_LIMIT_MAX
from app.db.models.oauth2_session import OAuth2SessionDB
from app.db.models.oauth2_token_pair import OAuth2TokenPairDB
from app.db.models.organization import OrganizationDB
from app.db.models.organization_membership import OrganizationMembershipDB
from app.db.models.user import UserDB
from app.identity.users.enums import OrganizationUserRole
from fastapi import FastAPI, status
from sqlalchemy import func, select, update

from tests.fixtures.auth import (
    current_user_id_for_email,
    issue_user_token,
    pre_session_csrf_headers,
    UserCredentials,
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
    assert sessions[0]["client_id"] == "test-user-client"
    assert sessions[0]["session_id"].startswith("oas_")
    assert sessions[0]["active"] is True
    assert "session_ended_at" not in sessions[0]

    headers = await pre_session_csrf_headers(client)
    revoke_response = await client.delete(
        f"{ORGANIZATION_OAUTH2_PATH}/sessions/{sessions[0]['session_id']}",
        headers=headers,
    )

    assert revoke_response.status_code == status.HTTP_200_OK
    assert revoke_response.json() == {
        "revoked_sessions": 1,
        "revoked_token_pairs": 1,
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
        f"{ORGANIZATION_OAUTH2_PATH}/clients/test-user-client/tokens",
        headers=headers,
    )

    assert response.status_code == status.HTTP_200_OK
    assert response.json() == {
        "revoked_sessions": 1,
        "revoked_token_pairs": 1,
    }


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
                OAuth2SessionDB.client_id == "test-user-client"
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
    session_public_id = sessions.json()["items"][0]["session_id"]
    headers = await pre_session_csrf_headers(client)

    response = await client.delete(
        f"{ORGANIZATION_OAUTH2_PATH}/sessions/{session_public_id}",
        headers=headers,
    )

    assert response.status_code == status.HTTP_200_OK
    assert response.json() == {
        "revoked_sessions": 0,
        "revoked_token_pairs": 1,
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
                OAuth2SessionDB.client_id == "test-user-client"
            )
        )
        assert session_id is not None
        await db_session.execute(
            update(OAuth2TokenPairDB)
            .where(OAuth2TokenPairDB.session_id == session_id)
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
    assert (
        first.json()["items"][0]["session_id"]
        != second.json()["items"][0]["session_id"]
    )


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
            .where(OAuth2SessionDB.client_id == "test-user-client")
            .values(organization_id=other_organization.id)
        )
        await db_session.commit()
    headers = await pre_session_csrf_headers(client)

    response = await client.delete(
        f"{ORGANIZATION_OAUTH2_PATH}/clients/test-user-client/tokens",
        headers=headers,
    )

    assert response.status_code == status.HTTP_200_OK
    assert response.json() == {"revoked_sessions": 0, "revoked_token_pairs": 0}
    async with app.state.core_session_factory() as db_session:
        remaining = await db_session.scalar(
            select(func.count())
            .select_from(OAuth2TokenPairDB)
            .join(OAuth2SessionDB, OAuth2SessionDB.id == OAuth2TokenPairDB.session_id)
            .where(OAuth2SessionDB.client_id == "test-user-client")
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
        await client.delete(f"{ORGANIZATION_OAUTH2_PATH}/sessions/oas_0000000XSNJFZ")
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
            .values(role=OrganizationUserRole.MEMBER)
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
        f"{ORGANIZATION_OAUTH2_PATH}/sessions/oas_0000000XSNJFZ",
        headers=headers,
    )
    missing_client = await client.delete(
        f"{ORGANIZATION_OAUTH2_PATH}/clients/missing-client/tokens",
        headers=headers,
    )
    repeated_client = await client.delete(
        f"{ORGANIZATION_OAUTH2_PATH}/clients/missing-client/tokens",
        headers=headers,
    )

    assert missing_session.status_code == status.HTTP_404_NOT_FOUND
    assert missing_session.json()["code"] == "OAUTH2_SESSION_NOT_FOUND"
    assert missing_client.status_code == status.HTTP_200_OK
    assert missing_client.json() == {
        "revoked_sessions": 0,
        "revoked_token_pairs": 0,
    }
    assert repeated_client.status_code == status.HTTP_200_OK
    assert repeated_client.json() == missing_client.json()
