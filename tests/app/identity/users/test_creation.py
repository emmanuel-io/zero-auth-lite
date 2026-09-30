"""Integration tests for shared user identity creation persistence."""

from datetime import datetime

import pytest
from app.db.models.organization import OrganizationDB
from app.db.models.organization_membership import OrganizationMembershipDB
from app.db.models.user import UserDB, UserEmailDB
from app.identity.users.commands import UserCreateCommand, UserOnboardingMode
from app.identity.users.creation import create_user_identity
from app.identity.users.enums import OrganizationMembershipRole, UserEmailStatus
from fastapi import FastAPI
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError


pytestmark = pytest.mark.integration
TEST_PASSWORD_HASH = "stored-password-hash"  # noqa: S105


async def _create_organization(app: FastAPI, *, name: str) -> OrganizationDB:
    """Persist an organization required by identity creation."""
    async with app.state.core_session_factory() as session:
        organization = OrganizationDB(name=name)
        session.add(organization)
        await session.commit()
        return organization


@pytest.mark.asyncio
@pytest.mark.parametrize("email_verified", [False, True])
async def test_create_user_identity_persists_required_rows(
    app: FastAPI, *, email_verified: bool
) -> None:
    """Create the user, membership, and correctly verified current email."""
    organization = await _create_organization(app, name=f"Creation {email_verified}")
    async with app.state.core_session_factory() as session:
        user, membership, user_email = await create_user_identity(
            session,
            command=UserCreateCommand(
                organization_id=organization.id,
                email=f"creation-{email_verified}@example.com",
                onboarding=UserOnboardingMode.INVITATION,
                role=OrganizationMembershipRole.ADMIN,
                email_verified=email_verified,
            ),
            hashed_password=TEST_PASSWORD_HASH,
        )

        persisted_user = await session.scalar(
            select(UserDB).where(UserDB.id == user.id)
        )
        persisted_membership = await session.scalar(
            select(OrganizationMembershipDB).where(
                OrganizationMembershipDB.user_id == user.id
            )
        )
        persisted_email = await session.scalar(
            select(UserEmailDB).where(UserEmailDB.user_id == user.id)
        )

    assert persisted_user is user
    assert persisted_user.hashed_password == TEST_PASSWORD_HASH
    assert persisted_membership is membership
    assert persisted_email is user_email
    assert membership.organization_id == organization.id
    assert membership.role is OrganizationMembershipRole.ADMIN
    assert user_email.status == UserEmailStatus.CURRENT
    assert isinstance(user_email.verified_at, datetime) is email_verified
    assert user.current_email is user_email


@pytest.mark.asyncio
async def test_create_user_identity_does_not_commit(app: FastAPI) -> None:
    """Leave commit ownership with the calling service."""
    organization = await _create_organization(app, name="Creation Rollback")
    async with app.state.core_session_factory() as session:
        await create_user_identity(
            session,
            command=UserCreateCommand(
                organization_id=organization.id,
                email="creation-rollback@example.com",
                onboarding=UserOnboardingMode.INVITATION,
            ),
            hashed_password=TEST_PASSWORD_HASH,
        )

    async with app.state.core_session_factory() as session:
        persisted_email = await session.scalar(
            select(UserEmailDB).where(
                UserEmailDB.normalized_email == "creation-rollback@example.com"
            )
        )

    assert persisted_email is None


@pytest.mark.asyncio
async def test_create_user_identity_propagates_email_collision(app: FastAPI) -> None:
    """Let the calling service translate an integrity collision."""
    organization = await _create_organization(app, name="Creation Collision")
    command = UserCreateCommand(
        organization_id=organization.id,
        email="creation-collision@example.com",
        onboarding=UserOnboardingMode.INVITATION,
    )
    async with app.state.core_session_factory() as session:
        await create_user_identity(
            session,
            command=command,
            hashed_password=TEST_PASSWORD_HASH,
        )
        await session.commit()

    async with app.state.core_session_factory() as session:
        with pytest.raises(IntegrityError):
            async with session.begin_nested():
                await create_user_identity(
                    session,
                    command=command,
                    hashed_password=TEST_PASSWORD_HASH,
                )
