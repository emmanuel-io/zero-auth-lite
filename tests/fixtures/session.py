"""Reusable browser-session database fixtures."""

from datetime import datetime, UTC

import pytest_asyncio
from app.browser_sessions.dtos import SessionCreateDTO, SessionReadDTO
from app.browser_sessions.mapping import to_session_dto
from app.db.models.browser_session import BrowserSessionDB
from app.db.models.organization import OrganizationDB
from app.db.models.organization_membership import OrganizationMembershipDB
from app.db.models.user import UserDB, UserEmailDB
from app.identity.users.enums import OrganizationUserRole, UserEmailStatus
from fastapi import FastAPI
from sqlalchemy import insert, select, update
from sqlalchemy.ext.asyncio import async_sessionmaker, AsyncSession


class BrowserSessionFixture:
    """Arrange and inspect browser-session rows without production stores."""

    def __init__(
        self,
        db_session: AsyncSession,
        session_factory: async_sessionmaker[AsyncSession],
    ) -> None:
        """Keep the isolated test database session."""
        self.db_session = db_session
        self.session_factory = session_factory

    async def create(self, *, dto: SessionCreateDTO) -> None:
        """Insert one browser-session row."""
        self.db_session.add(
            BrowserSessionDB(
                id=dto.stored_session_id,
                user_id=dto.user_id,
                csrf=dto.csrf,
                absolute_expires_at=dto.absolute_expires_at,
                expires_at=dto.expires_at,
                ip_hash=dto.ip_hash,
                last_seen_at=datetime.now(UTC),
                user_agent_hash=dto.user_agent_hash,
            )
        )
        await self.db_session.flush()

    async def read(self, *, session_id: str) -> SessionReadDTO | None:
        """Read one browser-session DTO."""
        row = await self.db_session.scalar(
            select(BrowserSessionDB).where(BrowserSessionDB.id == session_id)
        )
        return to_session_dto(row) if row is not None else None

    async def revoke(self, *, session_id: str, reason: str) -> bool:
        """Conditionally revoke one active browser session."""
        revoked_id = await self.db_session.scalar(
            update(BrowserSessionDB)
            .where(BrowserSessionDB.id == session_id)
            .where(BrowserSessionDB.revoked_at.is_(None))
            .values(revoked_at=datetime.now(UTC), revoked_reason=reason)
            .returning(BrowserSessionDB.id)
        )
        await self.db_session.flush()
        return revoked_id is not None


@pytest_asyncio.fixture
async def session_fixture(
    app: FastAPI, db_session: AsyncSession
) -> BrowserSessionFixture:
    """Provide browser-session row setup for service integration tests."""
    return BrowserSessionFixture(db_session, app.state.core_session_factory)


@pytest_asyncio.fixture
async def session_store_user_id(db_session: AsyncSession) -> int:
    """Create the user required by the relational session foreign key."""
    organization = (
        await db_session.execute(
            insert(OrganizationDB)
            .values(name="Session Tests")
            .returning(OrganizationDB)
        )
    ).scalar_one()
    user = (
        await db_session.execute(
            insert(UserDB)
            .values(
                hashed_password="unused-test-password-hash",  # noqa: S106
            )
            .returning(UserDB)
        )
    ).scalar_one()
    db_session.add(
        UserEmailDB(
            user_id=user.id,
            email="session-tests@example.com",
            normalized_email="session-tests@example.com",
            status=UserEmailStatus.CURRENT,
        )
    )
    db_session.add(
        OrganizationMembershipDB(
            user_id=user.id,
            organization_id=organization.id,
            role=OrganizationUserRole.MEMBER,
        )
    )
    await db_session.flush()
    return int(user.id)
