"""Listing and revocation workflows for browser sessions."""

from datetime import datetime, UTC
from typing import cast, TYPE_CHECKING

from sqlalchemy import delete, func, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.browser_sessions.dtos import SessionReadDTO
from app.browser_sessions.hashing import hash_session_id
from app.browser_sessions.mapping import to_session_dto
from app.browser_sessions.settings import SessionSettings
from app.db.models.browser_session import BrowserSessionDB
from app.public_ids import PublicId


if TYPE_CHECKING:
    from sqlalchemy.engine import CursorResult


class SessionRevocationService:
    """List, revoke, and clean up browser sessions."""

    def __init__(
        self,
        db_session: AsyncSession,
        settings: SessionSettings,
    ) -> None:
        """Initialize browser-session revocation workflows."""
        self.db_session = db_session
        self.settings = settings

    def _hash_session_id(self, *, session_id: str) -> str:
        """Return the configured database lookup digest for a raw session ID."""
        return hash_session_id(
            session_id=session_id,
            secret=self.settings.id_hash_secret.get_secret_value(),
        )

    async def logout(self, *, session_id: str) -> bool:
        """Revoke a specific browser session."""
        result = cast(
            "CursorResult[object]",
            await self.db_session.execute(
                update(BrowserSessionDB)
                .where(
                    BrowserSessionDB.id == self._hash_session_id(session_id=session_id)
                )
                .where(BrowserSessionDB.revoked_at.is_(None))
                .values(revoked_at=datetime.now(UTC), revoked_reason="logout")
            ),
        )
        await self.db_session.flush()
        return bool(result.rowcount)

    async def revoke_user_sessions(
        self,
        *,
        user_id: int,
        excluded_session_id: str | None = None,
        reason: str = "logout_all",
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
                != self._hash_session_id(session_id=excluded_session_id)
            )
        result = cast(
            "CursorResult[object]",
            await self.db_session.execute(
                stmt.values(revoked_at=datetime.now(UTC), revoked_reason=reason)
            ),
        )
        await self.db_session.flush()
        return int(result.rowcount or 0)

    async def cleanup_expired_sessions(self) -> int:
        """Delete one bounded batch of expired or revoked browser sessions."""
        now = datetime.now(UTC)
        expired_ids = (
            select(BrowserSessionDB.id)
            .where(
                (BrowserSessionDB.expires_at <= now)
                | (BrowserSessionDB.absolute_expires_at <= now)
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

    async def clear_all_sessions(self) -> int:
        """Delete every browser session as an explicit administrative operation."""
        result = cast(
            "CursorResult[object]",
            await self.db_session.execute(delete(BrowserSessionDB)),
        )
        await self.db_session.flush()
        return int(result.rowcount or 0)

    async def list_user_sessions(
        self,
        *,
        user_id: int,
        active_only: bool = True,
        limit: int = 100,
    ) -> list[SessionReadDTO]:
        """List browser sessions for a user."""
        now = datetime.now(UTC)
        stmt = select(BrowserSessionDB).where(BrowserSessionDB.user_id == user_id)
        if active_only:
            stmt = (
                stmt.where(BrowserSessionDB.revoked_at.is_(None))
                .where(BrowserSessionDB.expires_at > now)
                .where(BrowserSessionDB.absolute_expires_at > now)
            )
        rows = (
            await self.db_session.scalars(
                stmt.order_by(BrowserSessionDB.last_seen_at.desc()).limit(limit)
            )
        ).all()
        return [to_session_dto(row) for row in rows]

    async def revoke_user_session_by_public_id(
        self,
        *,
        public_id: int,
        user_id: int,
        reason: str = "user_revoked",
    ) -> bool:
        """Revoke one browser session owned by a user."""
        result = cast(
            "CursorResult[object]",
            await self.db_session.execute(
                update(BrowserSessionDB)
                .where(BrowserSessionDB.public_id == PublicId(public_id))
                .where(BrowserSessionDB.user_id == user_id)
                .where(BrowserSessionDB.revoked_at.is_(None))
                .values(revoked_at=func.now(), revoked_reason=reason)
            ),
        )
        await self.db_session.flush()
        return bool(result.rowcount)
