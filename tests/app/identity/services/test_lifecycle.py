"""Tests for actor-neutral user lifecycle behavior."""

import pytest
from app.db.models.organization_membership import OrganizationMembershipDB
from app.events.types import AccountVerificationRequested, InviteCreated
from app.identity.services.lifecycle_policy import EmailUpdatePolicy
from app.identity.users.commands import (
    UserCreateCommand,
    UserOnboardingMode,
    UserUpdateCommand,
)
from app.identity.users.enums import OrganizationUserRole
from app.identity.users.errors import (
    InactiveUserInvitationError,
    LastActiveOperatorError,
    LastActiveOrganizationAdminError,
)
from fastapi import FastAPI

from .helpers import (
    build_lifecycle,
    create_organization,
    create_user,
    FakeEventPublisher,
    load_user,
)


pytestmark = pytest.mark.integration


@pytest.mark.asyncio
async def test_lifecycle_creates_invited_user_and_publishes_event(
    app: FastAPI,
) -> None:
    """Hash generated credentials before persisting an invited user."""
    organization = await create_organization(app, name="Lifecycle Invite")
    publisher = FakeEventPublisher()
    async with app.state.core_session_factory() as db_session:
        lifecycle = build_lifecycle(app, db_session, publisher=publisher)
        created, membership = await lifecycle.create(
            command=UserCreateCommand(
                organization_id=organization.id,
                email="lifecycle-invite@example.com",
                onboarding=UserOnboardingMode.INVITATION,
            ),
        )

    assert created.hashed_password
    assert membership.role is OrganizationUserRole.MEMBER
    assert any(isinstance(event, InviteCreated) for event in publisher.events)


@pytest.mark.asyncio
async def test_lifecycle_requests_verification_for_user_with_password(
    app: FastAPI,
) -> None:
    """Make administrator-created credentials usable after email verification."""
    organization = await create_organization(app, name="Lifecycle Password")
    publisher = FakeEventPublisher()
    async with app.state.core_session_factory() as db_session:
        lifecycle = build_lifecycle(app, db_session, publisher=publisher)
        created, _membership = await lifecycle.create(
            command=UserCreateCommand(
                organization_id=organization.id,
                email="lifecycle-password@example.com",
                password="S3cretPass1!",  # noqa: S106
                onboarding=UserOnboardingMode.PASSWORD_VERIFICATION,
            ),
        )

    event = publisher.events[0]
    assert isinstance(event, AccountVerificationRequested)
    assert event.user_public_id == created.public_id
    assert event.user_email_id == created.current_email.id


@pytest.mark.asyncio
async def test_lifecycle_uses_explicit_email_update_policy(app: FastAPI) -> None:
    """Distinguish pending self-service changes from administrator corrections."""
    organization = await create_organization(app, name="Lifecycle Email")
    verified = await create_user(
        app,
        organization_id=organization.id,
        email="lifecycle-verified@example.com",
    )
    unverified = await create_user(
        app,
        organization_id=organization.id,
        email="lifecycle-unverified@example.com",
        email_verified=False,
    )
    async with app.state.core_session_factory() as db_session:
        lifecycle = build_lifecycle(app, db_session)
        verified_row = await load_user(db_session, verified.id)
        verified_role = await db_session.get(OrganizationMembershipDB, verified.id)
        unverified_row = await load_user(db_session, unverified.id)
        unverified_role = await db_session.get(OrganizationMembershipDB, unverified.id)
        assert verified_role is not None
        assert unverified_role is not None
        pending, _pending_role = await lifecycle.update(
            target=verified_row,
            membership=verified_role,
            command=UserUpdateCommand(email="lifecycle-pending@example.com"),
            email_policy=EmailUpdatePolicy.PENDING_VERIFICATION_ONLY,
        )
        direct, _direct_role = await lifecycle.update(
            target=unverified_row,
            membership=unverified_role,
            command=UserUpdateCommand(email="lifecycle-direct@example.com"),
            email_policy=EmailUpdatePolicy.DIRECT_IF_UNVERIFIED,
        )

    assert pending.pending_email == "lifecycle-pending@example.com"
    assert direct.email == "lifecycle-direct@example.com"


@pytest.mark.asyncio
async def test_lifecycle_protects_last_organization_admin(app: FastAPI) -> None:
    """Apply the final-administrator invariant independently of the caller."""
    organization = await create_organization(app, name="Lifecycle Last Admin")
    admin = await create_user(
        app,
        organization_id=organization.id,
        email="lifecycle-admin@example.com",
        role=OrganizationUserRole.ADMIN,
    )
    async with app.state.core_session_factory() as db_session:
        lifecycle = build_lifecycle(app, db_session)
        target = await load_user(db_session, admin.id)
        membership = await db_session.get(OrganizationMembershipDB, admin.id)
        assert membership is not None
        with pytest.raises(LastActiveOrganizationAdminError):
            await lifecycle.delete(targets=((target, membership),))


@pytest.mark.asyncio
async def test_lifecycle_protects_last_operator(app: FastAPI) -> None:
    """Preserve at least one active, verified server operator."""
    organization = await create_organization(app, name="Lifecycle Last Operator")
    operator = await create_user(
        app,
        organization_id=organization.id,
        email="lifecycle-operator@example.com",
        is_operator=True,
    )
    async with app.state.core_session_factory() as db_session:
        lifecycle = build_lifecycle(app, db_session)
        target = await load_user(db_session, operator.id)
        membership = await db_session.get(OrganizationMembershipDB, operator.id)
        assert membership is not None
        with pytest.raises(LastActiveOperatorError):
            await lifecycle.delete(targets=((target, membership),))


@pytest.mark.asyncio
async def test_lifecycle_rejects_invitation_for_inactive_user(app: FastAPI) -> None:
    """Do not publish invitations for deactivated identities."""
    organization = await create_organization(app, name="Lifecycle Inactive Invite")
    user = await create_user(
        app,
        organization_id=organization.id,
        email="lifecycle-inactive@example.com",
        is_active=False,
        email_verified=False,
    )
    async with app.state.core_session_factory() as db_session:
        lifecycle = build_lifecycle(app, db_session)
        target = await load_user(db_session, user.id)
        with pytest.raises(InactiveUserInvitationError):
            await lifecycle.resend_invitation(target=target)
