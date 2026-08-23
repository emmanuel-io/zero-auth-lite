"""Shared setup for actor-focused user service tests."""

from dataclasses import dataclass
from datetime import datetime, UTC
from typing import cast

from app.db.models.organization import OrganizationDB
from app.db.models.organization_membership import OrganizationMembershipDB
from app.db.models.user import UserDB, UserEmailDB
from app.enums import Role
from app.events.base import BaseEvent
from app.identity.services.lifecycle import UserLifecycleService
from app.identity.users.emails import active_email_loader
from app.identity.users.enums import OrganizationUserRole, UserEmailStatus
from app.password.pwdlib_hasher import PwdlibPasswordHasher
from app.public_ids import PublicId
from app.security.dtos import BrowserUserPrincipalContext
from app.security.session_revocation import SecuritySessionRevocationService
from fastapi import FastAPI
from sqlalchemy import insert, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm.attributes import set_committed_value


TEST_PASSWORD = "S3cretPass1!"  # noqa: S105
PASSWORD_HASHER = PwdlibPasswordHasher()


@dataclass(frozen=True, slots=True)
class CreatedUser:
    """Persisted user and organization membership for service tests."""

    user: UserDB
    membership: OrganizationMembershipDB

    @property
    def id(self) -> int:
        """Return the internal user identifier."""
        return self.user.id

    @property
    def public_id(self) -> PublicId:
        """Return the public user identifier."""
        return self.user.public_id

    @property
    def email(self) -> str:
        """Return the persisted email address."""
        return self.user.email


class FakeEventPublisher:
    """Record lifecycle events without dispatching them."""

    def __init__(self) -> None:
        """Initialize the event collection."""
        self.events: list[BaseEvent] = []

    async def publish(self, event: BaseEvent) -> None:
        """Record one event."""
        self.events.append(event)


async def create_organization(app: FastAPI, *, name: str) -> OrganizationDB:
    """Persist an organization for a service test."""
    async with app.state.core_session_factory() as db_session:
        organization = (
            await db_session.execute(
                insert(OrganizationDB).values(name=name).returning(OrganizationDB)
            )
        ).scalar_one()
        await db_session.commit()
        return cast("OrganizationDB", organization)


async def create_user(  # noqa: PLR0913
    app: FastAPI,
    *,
    organization_id: int,
    email: str,
    is_active: bool = True,
    role: OrganizationUserRole = OrganizationUserRole.MEMBER,
    is_operator: bool = False,
    email_verified: bool = True,
) -> CreatedUser:
    """Persist a user for a service test."""
    async with app.state.core_session_factory() as db_session:
        user = (
            await db_session.execute(
                insert(UserDB)
                .values(
                    hashed_password=PASSWORD_HASHER.hash(TEST_PASSWORD),
                    is_active=is_active,
                    is_operator=is_operator,
                )
                .returning(UserDB)
            )
        ).scalar_one()
        user_email = UserEmailDB(
            user_id=user.id,
            email=email,
            normalized_email=email.lower(),
            status=UserEmailStatus.CURRENT,
            verified_at=datetime.now(UTC) if email_verified else None,
        )
        db_session.add(user_email)
        set_committed_value(user, "emails", [user_email])
        membership = (
            await db_session.execute(
                insert(OrganizationMembershipDB)
                .values(
                    user_id=user.id,
                    organization_id=organization_id,
                    role=role,
                )
                .returning(OrganizationMembershipDB)
            )
        ).scalar_one()
        await db_session.commit()
        return CreatedUser(
            user=cast("UserDB", user),
            membership=cast("OrganizationMembershipDB", membership),
        )


async def load_user(db_session: AsyncSession, user_id: int) -> UserDB:
    """Load a user with the active email projection required by services."""
    user = await db_session.scalar(
        select(UserDB).where(UserDB.id == user_id).options(active_email_loader())
    )
    assert user is not None
    return user


def user_context(
    user: CreatedUser, *, role: Role | None = None
) -> BrowserUserPrincipalContext:
    """Build a principal context for one actor role."""
    return BrowserUserPrincipalContext(
        user_id=user.id,
        organization_id=user.membership.organization_id,
        session_id="test-session",
        roles=frozenset({role}) if role is not None else frozenset(),
    )


def build_lifecycle(
    app: FastAPI,
    db_session: AsyncSession,
    *,
    publisher: FakeEventPublisher | None = None,
) -> UserLifecycleService:
    """Build the concrete lifecycle collaborators for a test transaction."""
    return UserLifecycleService(
        db_session=db_session,
        password_hasher=app.state.password_hasher,
        event_publisher=publisher or FakeEventPublisher(),
        security_revocation=SecuritySessionRevocationService(db_session=db_session),
        session_factory=app.state.core_session_factory,
    )
