"""Cross-cutting authorization tests for the server administration API."""

import httpx
import pytest
from app.db.models.organization_membership import OrganizationMembershipDB
from app.db.models.user import UserDB
from app.identity.users.enums import OrganizationUserRole
from fastapi import FastAPI, status
from sqlalchemy import select, update

from tests.fixtures.auth import (
    current_user_id_for_email,
    issue_user_token,
    UserCredentials,
)
from tests.routes.api.helpers import login_headers


pytestmark = pytest.mark.api


@pytest.mark.asyncio
async def test_anonymous_callers_cannot_access_admin_route_families(
    client: httpx.AsyncClient,
) -> None:
    """Require authentication throughout the server control plane."""
    responses = [
        await client.get("/api/v1/admin/organizations"),
        await client.get("/api/v1/admin/users"),
        await client.get("/api/v1/admin/oauth2/clients"),
        await client.delete("/api/v1/admin/sessions", params={"status": "expired"}),
    ]

    assert {response.status_code for response in responses} == {
        status.HTTP_401_UNAUTHORIZED
    }


@pytest.mark.asyncio
@pytest.mark.parametrize("user_kind", ["member", "organization_admin"])
async def test_non_operators_cannot_access_admin_route_families(
    app: FastAPI,
    client: httpx.AsyncClient,
    verified_user_credentials: UserCredentials,
    user_kind: str,
) -> None:
    """Reject standard users and organization admins from every control-plane family."""
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
            .values(
                role=(
                    OrganizationUserRole.ADMIN
                    if user_kind == "organization_admin"
                    else OrganizationUserRole.MEMBER
                )
            )
        )
        await db_session.execute(
            update(UserDB)
            .where(
                UserDB.id == current_user_id_for_email(verified_user_credentials.email)
            )
            .values(is_operator=False)
        )
        await db_session.commit()
    headers = await login_headers(client, verified_user_credentials)

    responses = [
        await client.get("/api/v1/admin/organizations"),
        await client.get("/api/v1/admin/users"),
        await client.get("/api/v1/admin/oauth2/clients"),
        await client.delete(
            "/api/v1/admin/sessions",
            params={"status": "expired"},
            headers=headers,
        ),
    ]

    assert {response.status_code for response in responses} == {
        status.HTTP_403_FORBIDDEN
    }


@pytest.mark.asyncio
async def test_operator_bearer_requires_each_admin_scope(
    app: FastAPI,
    client: httpx.AsyncClient,
    verified_user_credentials: UserCredentials,
) -> None:
    """Keep operator authority insufficient without the route's OAuth2 scope."""
    token_response = await issue_user_token(
        app,
        client,
        verified_user_credentials,
        scope="profile:read",
    )
    assert token_response.status_code == status.HTTP_200_OK
    headers = {"Authorization": f"Bearer {token_response.json()['access_token']}"}

    responses = [
        await client.get("/api/v1/admin/organizations", headers=headers),
        await client.get("/api/v1/admin/users", headers=headers),
        await client.get("/api/v1/admin/oauth2/clients", headers=headers),
        await client.delete(
            "/api/v1/admin/sessions",
            params={"status": "expired"},
            headers=headers,
        ),
    ]

    assert {response.status_code for response in responses} == {
        status.HTTP_403_FORBIDDEN
    }


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "route_case",
    [
        ("organizations:read", "get", "/api/v1/admin/organizations"),
        ("users:read", "get", "/api/v1/admin/users"),
        ("oauth2_clients:read", "get", "/api/v1/admin/oauth2/clients"),
        ("users:write", "delete", "/api/v1/admin/sessions?status=expired"),
    ],
)
async def test_operator_bearer_accepts_matching_admin_scope(
    app: FastAPI,
    client: httpx.AsyncClient,
    verified_user_credentials: UserCredentials,
    route_case: tuple[str, str, str],
) -> None:
    """Accept operator bearers only on the matching control-plane family."""
    scope, method, path = route_case
    token_response = await issue_user_token(
        app,
        client,
        verified_user_credentials,
        scope=scope,
    )
    assert token_response.status_code == status.HTTP_200_OK

    response = await client.request(
        method,
        path,
        headers={"Authorization": f"Bearer {token_response.json()['access_token']}"},
    )

    assert response.status_code == status.HTTP_200_OK


@pytest.mark.asyncio
@pytest.mark.parametrize("csrf_mode", ["missing", "invalid"])
async def test_cookie_authenticated_admin_writes_require_valid_csrf(
    client: httpx.AsyncClient,
    verified_user_credentials: UserCredentials,
    csrf_mode: str,
) -> None:
    """Reject valid operator sessions with missing or mismatched CSRF tokens."""
    auth_headers = await login_headers(client, verified_user_credentials)
    users_response = await client.get("/api/v1/admin/users")
    assert users_response.status_code == status.HTTP_200_OK
    organization_id = users_response.json()["items"][0]["organization_id"]
    write_headers = {"Origin": str(client.base_url).rstrip("/")}
    if csrf_mode == "invalid":
        csrf_header = next(
            name for name in auth_headers if name.lower().startswith("x-csrf")
        )
        write_headers[csrf_header] = "invalid-csrf-token"

    responses = [
        await client.post(
            "/api/v1/admin/organizations",
            json={"name": "Missing CSRF Organization"},
            headers=write_headers,
        ),
        await client.post(
            "/api/v1/admin/users",
            json={
                "organization_id": organization_id,
                "email": "missing-csrf@example.com",
            },
            headers=write_headers,
        ),
        await client.post(
            "/api/v1/admin/oauth2/clients",
            json={
                "name": "Missing CSRF Client",
                "grant_types": ["client_credentials"],
                "is_confidential": True,
            },
            headers=write_headers,
        ),
        await client.delete(
            "/api/v1/admin/sessions",
            params={"status": "expired"},
            headers=write_headers,
        ),
    ]

    assert {response.status_code for response in responses} == {
        status.HTTP_403_FORBIDDEN
    }
