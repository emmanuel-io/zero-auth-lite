"""Black-box tests for public user registration."""

import httpx
import pytest
from app.db.models.organization import OrganizationDB
from app.db.models.organization_membership import OrganizationMembershipDB
from app.db.models.user import UserDB, UserEmailDB
from app.identity.users.enums import OrganizationUserRole, UserEmailStatus
from fastapi import FastAPI, status
from sqlalchemy import insert, select


pytestmark = pytest.mark.api

HTTP_CREATED = 201


@pytest.mark.asyncio
async def test_register_creates_a_named_organization_and_initial_user(
    app: FastAPI,
    client: httpx.AsyncClient,
) -> None:
    """Assert public registration creates a named organization and its first user."""
    response = await client.post(
        "/api/v1/auth/register",
        json={
            "email": "minimal-register@example.com",
            "password": "S3cretPass1!",
            "organization_name": "Minimal Registration",
        },
    )

    body = response.json()

    assert response.status_code == HTTP_CREATED
    assert body["email"] == "minimal-register@example.com"
    assert body["role"] == "admin"
    assert body["email_verified"] is False
    assert body["organization_id"] is not None
    async with app.state.core_session_factory() as session:
        email_owner = await session.scalar(
            select(UserEmailDB.user_id).where(
                UserEmailDB.normalized_email == "minimal-register@example.com",
                UserEmailDB.status == UserEmailStatus.CURRENT,
            )
        )
    assert email_owner is not None


@pytest.mark.asyncio
@pytest.mark.negative
async def test_register_rejects_an_email_reserved_as_pending(
    app: FastAPI,
    client: httpx.AsyncClient,
) -> None:
    """Prevent registration from claiming another user's pending email."""
    async with app.state.core_session_factory() as session:
        organization = (
            await session.execute(
                insert(OrganizationDB)
                .values(name="Pending Email Organization")
                .returning(OrganizationDB)
            )
        ).scalar_one()
        user = (
            await session.execute(
                insert(UserDB)
                .values(
                    first_name="Pending",
                    last_name="Owner",
                    hashed_password="unused-password-hash",  # noqa: S106
                    is_active=True,
                )
                .returning(UserDB)
            )
        ).scalar_one()
        session.add_all(
            [
                UserEmailDB(
                    user_id=user.id,
                    email="current@example.com",
                    normalized_email="current@example.com",
                    status=UserEmailStatus.CURRENT,
                    verified_at=user.created_at,
                ),
                UserEmailDB(
                    user_id=user.id,
                    email="reserved@example.com",
                    normalized_email="reserved@example.com",
                    status=UserEmailStatus.PENDING,
                ),
            ]
        )
        session.add(
            OrganizationMembershipDB(
                user_id=user.id,
                organization_id=organization.id,
                role=OrganizationUserRole.ADMIN,
            )
        )
        await session.commit()

    response = await client.post(
        "/api/v1/auth/register",
        json={
            "email": "Reserved@Example.com",
            "password": "S3cretPass1!",
            "organization_name": "Reserved Registration",
        },
    )

    assert response.status_code == status.HTTP_409_CONFLICT
    assert response.json()["code"] == "ALREADY_EXISTS"
