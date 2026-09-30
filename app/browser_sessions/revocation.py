"""Listing and revocation workflows for browser sessions."""

from datetime import datetime, UTC
from typing import cast, TYPE_CHECKING
from uuid import UUID

from sqlalchemy import delete, func, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.browser_sessions.dtos import BrowserSessionPageDTO
from app.browser_sessions.enums import BrowserSessionRevocationReason
from app.browser_sessions.hashing import hash_configured_session_id
from app.browser_sessions.mapping import to_session_dto
from app.browser_sessions.settings import BrowserSessionSettings
from app.db.models.browser_session import BrowserSessionDB
from app.db.models.organization_membership import OrganizationMembershipDB


if TYPE_CHECKING:
    from sqlalchemy.engine import CursorResult


class BrowserSessionRevocationService:
    """List, revoke, and clean up browser sessions."""

    def __init__(
        self,
        db_session: AsyncSession,
        settings: BrowserSessionSettings,
    ) -> None:
        """Initialize browser-session revocation workflows."""
        self.db_session = db_session
        self.settings = settings

    async def logout(self, *, session_id: str) -> bool:
        """Revoke a specific browser session."""
        result = cast(
            "CursorResult[object]",
            await self.db_session.execute(
                update(BrowserSessionDB)
                .where(
                    BrowserSessionDB.id
                    == hash_configured_session_id(
                        session_id=session_id,
                        settings=self.settings,
                    )
                )
                .where(BrowserSessionDB.revoked_at.is_(None))
                .values(
                    revoked_at=datetime.now(UTC),
                    revoked_reason=BrowserSessionRevocationReason.LOGOUT,
                )
            ),
        )
        await self.db_session.flush()
        return bool(result.rowcount)

    async def revoke_user_sessions(
        self,
        *,
        user_id: int,
        excluded_session_id: str | None = None,
        reason: BrowserSessionRevocationReason = (
            BrowserSessionRevocationReason.LOGOUT_ALL
        ),
    ) -> int:
        """Revoke a user's sessions, optionally preserving one session."""
        stmt = (
            update(BrowserSessionDB)
            .where(BrowserSessionDB.user_id == user_id)
            .where(BrowserSessionDB.revoked_at.is_(None))
        )
        if excluded_session_id is not None:
            stmt = stmt.where(
                BrowserSessionDB.id
                != hash_configured_session_id(
                    session_id=excluded_session_id,
                    settings=self.settings,
                )
            )
        result = cast(
            "CursorResult[object]",
            await self.db_session.execute(
                stmt.values(revoked_at=datetime.now(UTC), revoked_reason=reason)
            ),
        )
        await self.db_session.flush()
        return int(result.rowcount or 0)

    async def cleanup_terminal_sessions(self, *, now: datetime | None = None) -> int:
        """Delete one bounded batch of expired or revoked browser sessions."""
        cutoff = now or datetime.now(UTC)
        expired_ids = (
            select(BrowserSessionDB.id)
            .where(
                (BrowserSessionDB.expires_at <= cutoff)
                | (BrowserSessionDB.absolute_expires_at <= cutoff)
                | (BrowserSessionDB.revoked_at.is_not(None))
            )
            .order_by(BrowserSessionDB.expires_at, BrowserSessionDB.id)
            .limit(self.settings.cleanup_batch_size)
        )
        result = cast(
            "CursorResult[object]",
            await self.db_session.execute(
                delete(BrowserSessionDB).where(BrowserSessionDB.id.in_(expired_ids))
            ),
        )
        await self.db_session.flush()
        return int(result.rowcount or 0)

    async def delete_all_sessions(self) -> int:
        """Delete every browser session as an explicit administrative operation."""
        result = cast(
            "CursorResult[object]",
            await self.db_session.execute(delete(BrowserSessionDB)),
        )
        await self.db_session.flush()
        return int(result.rowcount or 0)

    async def delete_user_sessions(self, *, user_id: int) -> int:
        """Delete every browser session belonging to one user."""
        result = cast(
            "CursorResult[object]",
            await self.db_session.execute(
                delete(BrowserSessionDB).where(BrowserSessionDB.user_id == user_id)
            ),
        )
        await self.db_session.flush()
        return int(result.rowcount or 0)

    async def delete_organization_sessions(self, *, organization_id: int) -> int:
        """Delete browser sessions belonging to one organization's users."""
        organization_user_ids = select(OrganizationMembershipDB.user_id).where(
            OrganizationMembershipDB.organization_id == organization_id
        )
        result = cast(
            "CursorResult[object]",
            await self.db_session.execute(
                delete(BrowserSessionDB).where(
                    BrowserSessionDB.user_id.in_(organization_user_ids)
                )
            ),
        )
        await self.db_session.flush()
        return int(result.rowcount or 0)

    async def list_user_sessions(
        self,
        *,
        user_id: int,
        active_only: bool = True,
        offset: int = 0,
        limit: int = 100,
    ) -> BrowserSessionPageDTO:
        """List one page of browser sessions for a user."""
        now = datetime.now(UTC)
        stmt = select(BrowserSessionDB).where(BrowserSessionDB.user_id == user_id)
        if active_only:
            stmt = (
                stmt.where(BrowserSessionDB.revoked_at.is_(None))
                .where(BrowserSessionDB.expires_at > now)
                .where(BrowserSessionDB.absolute_expires_at > now)
            )
        total = await self.db_session.scalar(
            stmt.with_only_columns(func.count(), maintain_column_froms=True)
        )
        rows = (
            await self.db_session.scalars(
                stmt.order_by(
                    BrowserSessionDB.last_seen_at.desc(),
                    BrowserSessionDB.public_id.desc(),
                )
                .offset(offset)
                .limit(limit)
            )
        ).all()
        return BrowserSessionPageDTO(
            items=[to_session_dto(row) for row in rows],
            total=int(total or 0),
        )

    async def revoke_user_session_by_public_id(
        self,
        *,
        public_id: UUID,
        user_id: int,
        reason: BrowserSessionRevocationReason = (
            BrowserSessionRevocationReason.USER_REVOKED
        ),
    ) -> bool:
        """Revoke one browser session owned by a user."""
        result = cast(
            "CursorResult[object]",
            await self.db_session.execute(
                update(BrowserSessionDB)
                .where(BrowserSessionDB.public_id == public_id)
                .where(BrowserSessionDB.user_id == user_id)
                .where(BrowserSessionDB.revoked_at.is_(None))
                .values(revoked_at=func.now(), revoked_reason=reason)
            ),
        )
        await self.db_session.flush()
        return bool(result.rowcount)
