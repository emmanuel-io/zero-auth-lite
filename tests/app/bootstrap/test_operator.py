"""Tests for first-run operator bootstrap."""

import pytest
from app.bootstrap.operator import bootstrap_operator_user
from app.bootstrap.settings import BootstrapSettings
from app.db.models.organization import OrganizationDB
from app.db.models.organization_membership import OrganizationMembershipDB
from app.db.models.user import UserDB, UserEmailDB
from app.identity.public_ids import format_organization_id
from app.identity.users.enums import OrganizationUserRole
from fastapi import FastAPI
from pydantic import SecretStr
from sqlalchemy import func, insert, select


pytestmark = pytest.mark.integration
EXPECTED_ORGANIZATION_COUNT_WITH_COLLISIONS = 3


@pytest.mark.asyncio
async def test_bootstrap_creates_own_organization_when_display_names_collide(
    app: FastAPI,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Treat the bootstrap organization name as a non-unique display label."""
    settings = BootstrapSettings(
        operator_email="bootstrap@example.com",
        operator_password=SecretStr("Bootstrap-Pass1!"),
        organization_name="Shared name",
    )
    async with app.state.core_session_factory() as db_session:
        await db_session.execute(
            insert(OrganizationDB),
            [{"name": "Shared name"}, {"name": "Shared name"}],
        )
        await db_session.commit()

        await bootstrap_operator_user(
            db_session=db_session,
            settings=settings,
            password_hasher=app.state.password_hasher,
        )
        organization_count = await db_session.scalar(
            select(func.count()).select_from(OrganizationDB)
        )
        row = (
            await db_session.execute(
                select(UserDB, OrganizationMembershipDB)
                .join(
                    OrganizationMembershipDB,
                    OrganizationMembershipDB.user_id == UserDB.id,
                )
                .join(UserEmailDB, UserEmailDB.user_id == UserDB.id)
                .where(UserEmailDB.normalized_email == "bootstrap@example.com")
            )
        ).one_or_none()
        assert row is not None
        organization = await db_session.get(OrganizationDB, row[1].organization_id)
        assert organization is not None

    assert organization_count == EXPECTED_ORGANIZATION_COUNT_WITH_COLLISIONS
    user, membership = row
    assert membership.role is OrganizationUserRole.ADMIN
    assert user.is_operator
    assert "event=bootstrap_operator_created" in caplog.text
    assert "outcome=success" in caplog.text
    assert "reason=first_user_bootstrap" in caplog.text
    assert (
        f"organization_id={format_organization_id(organization.public_id)}"
        in caplog.text
    )
    assert f"organization_id={organization.public_id}" not in caplog.text


@pytest.mark.asyncio
async def test_bootstrap_is_idempotent_after_the_first_user(app: FastAPI) -> None:
    """Skip subsequent bootstrap attempts once one user exists."""
    settings = BootstrapSettings(
        operator_email="bootstrap@example.com",
        operator_password=SecretStr("Bootstrap-Pass1!"),
    )
    async with app.state.core_session_factory() as db_session:
        await bootstrap_operator_user(
            db_session=db_session,
            settings=settings,
            password_hasher=app.state.password_hasher,
        )
        await bootstrap_operator_user(
            db_session=db_session,
            settings=settings,
            password_hasher=app.state.password_hasher,
        )
        organization_count = await db_session.scalar(
            select(func.count()).select_from(OrganizationDB)
        )
        user_count = await db_session.scalar(select(func.count()).select_from(UserDB))

    assert organization_count == 1
    assert user_count == 1
