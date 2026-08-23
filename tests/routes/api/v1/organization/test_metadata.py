"""Black-box tests for `/api/v1/organization` metadata administration."""

import re

import httpx
import pytest
from app.db.models.organization_membership import OrganizationMembershipDB
from app.db.models.user import UserDB
from app.identity.users.enums import OrganizationUserRole
from app.public_ids import PUBLIC_ID_PAYLOAD_PATTERN
from fastapi import FastAPI, status
from sqlalchemy import select, update

from tests.fixtures.auth import current_user_id_for_email, UserCredentials
from tests.routes.api.helpers import login_headers


pytestmark = pytest.mark.api


@pytest.mark.asyncio
async def test_organization_admin_can_read_and_patch_current_organization(
    app: FastAPI,
    client: httpx.AsyncClient,
    verified_user_credentials: UserCredentials,
) -> None:
    """Assert organization metadata is resolved from the authenticated organization."""
    async with app.state.core_session_factory() as db_session:
        await db_session.execute(
            update(UserDB)
            .where(
                UserDB.id == current_user_id_for_email(verified_user_credentials.email)
            )
            .values(is_operator=False)
        )
        await db_session.commit()
    headers = await login_headers(client, verified_user_credentials)

    read_response = await client.get("/api/v1/organization")
    patch_response = await client.patch(
        "/api/v1/organization",
        json={"name": "Renamed Organization"},
        headers=headers,
    )

    assert read_response.status_code == status.HTTP_200_OK
    assert read_response.json()["name"] == "Test Organization"
    assert re.fullmatch(rf"org_{PUBLIC_ID_PAYLOAD_PATTERN}", read_response.json()["id"])
    assert patch_response.status_code == status.HTTP_200_OK
    assert patch_response.json()["name"] == "Renamed Organization"


@pytest.mark.asyncio
@pytest.mark.negative
async def test_operator_without_organization_admin_role_cannot_patch_current_org(
    app: FastAPI,
    client: httpx.AsyncClient,
    verified_user_credentials: UserCredentials,
) -> None:
    """Assert global operator permissions do not grant organization-scoped writes."""
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
    headers = await login_headers(client, verified_user_credentials)

    response = await client.patch(
        "/api/v1/organization",
        json={"name": "Operator Rename"},
        headers=headers,
    )

    assert response.status_code == status.HTTP_403_FORBIDDEN
    assert response.json()["code"] == "FORBIDDEN_OPERATION"


@pytest.mark.asyncio
async def test_organization_member_cannot_read_organization_administration_metadata(
    app: FastAPI,
    client: httpx.AsyncClient,
    verified_user_credentials: UserCredentials,
) -> None:
    """Require organization-admin authority in addition to organization:read access."""
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
            .values(is_operator=False)
        )
        await db_session.commit()
    await login_headers(client, verified_user_credentials)

    response = await client.get("/api/v1/organization")

    assert response.status_code == status.HTTP_403_FORBIDDEN
    assert response.json()["code"] == "FORBIDDEN_OPERATION"


@pytest.mark.asyncio
@pytest.mark.negative
async def test_current_organization_requires_authentication(
    client: httpx.AsyncClient,
) -> None:
    """Assert organization metadata is unavailable to anonymous callers."""
    response = await client.get("/api/v1/organization")

    assert response.status_code == status.HTTP_401_UNAUTHORIZED
