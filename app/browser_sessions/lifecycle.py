"""Persistence resolution and expiry sliding for browser sessions."""

from dataclasses import replace
from datetime import datetime, timedelta, UTC

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.browser_sessions.dtos import (
    SessionReadDTO,
    SessionSlideResultDTO,
)
from app.browser_sessions.errors import SessionInvalidError
from app.browser_sessions.hashing import hash_session_id
from app.browser_sessions.mapping import to_session_dto
from app.browser_sessions.settings import SessionSettings
from app.db.models.browser_session import BrowserSessionDB
from app.db.models.organization import OrganizationDB
from app.db.models.organization_membership import OrganizationMembershipDB
from app.db.models.user import UserDB
from app.identity.dtos import (
    IdentityUserDTO,
)
from app.identity.mapping import to_identity
from app.identity.users.emails import active_email_loader


class SessionLifecycleService:
    """Resolve browser-session persistence and slide its expiry."""

    def __init__(
        self,
        db_session: AsyncSession,
        settings: SessionSettings,
    ) -> None:
        """Initialize browser-session lifecycle workflows."""
        self.db_session = db_session
        self.settings = settings

    def _hash_session_id(self, *, session_id: str) -> str:
        """Return the configured database lookup digest for a raw session ID."""
        return hash_session_id(
            session_id=session_id,
            secret=self.settings.id_hash_secret.get_secret_value(),
        )

    def stored_session_id(self, *, session_id: str) -> str:
        """Return the stored digest for a raw browser session ID."""
        return self._hash_session_id(session_id=session_id)

    async def get_session_csrf_state(self, *, session_id: str) -> SessionReadDTO:
        """Return the stored state for a valid browser session."""
        return await self.load_session(session_id=session_id)

    async def get_session_csrf(self, *, session_id: str) -> str:
        """Return the CSRF token for a valid browser session."""
        session_obj = await self.get_session_csrf_state(session_id=session_id)
        return session_obj.csrf

    async def load_session(self, *, session_id: str) -> SessionReadDTO:
        """Load and validate a session without recording browser activity."""
        session_id_hash = self._hash_session_id(session_id=session_id)
        row = await self.db_session.scalar(
            select(BrowserSessionDB).where(BrowserSessionDB.id == session_id_hash)
        )
        session_obj = to_session_dto(row) if row is not None else None
        if session_obj is None:
            raise SessionInvalidError
        now = datetime.now(UTC)
        if session_obj.revoked_at is not None:
            raise SessionInvalidError
        if session_obj.expires_at <= now or session_obj.absolute_expires_at <= now:
            raise SessionInvalidError
        return session_obj

    async def slide_session(self, *, session: SessionReadDTO) -> SessionSlideResultDTO:
        """Record activity and extend one already validated browser session."""
        patch_expires_at = None
        now = datetime.now(UTC)
        if (session.expires_at - now) <= timedelta(seconds=self.settings.slide_seconds):
            patch_expires_at = min(
                now + timedelta(seconds=self.settings.ttl_seconds),
                session.absolute_expires_at,
            )
        record_activity = (now - session.last_seen_at) >= timedelta(
            seconds=self.settings.slide_seconds
        )
        effective_expires_at = session.expires_at
        if patch_expires_at is not None and patch_expires_at > effective_expires_at:
            effective_expires_at = patch_expires_at
        extend_expiry = effective_expires_at > session.expires_at
        if extend_expiry or record_activity:
            values = {"last_seen_at": now}
            if extend_expiry:
                values["expires_at"] = effective_expires_at
            await self.db_session.execute(
                update(BrowserSessionDB)
                .where(BrowserSessionDB.id == session.stored_session_id)
                .values(**values)
            )
            await self.db_session.flush()
        return SessionSlideResultDTO(
            session=replace(
                session,
                expires_at=effective_expires_at,
                last_seen_at=(
                    now if extend_expiry or record_activity else session.last_seen_at
                ),
            ),
            expiry_extended=extend_expiry,
        )

    async def get_user_by_id(self, *, user_id: int) -> IdentityUserDTO | None:
        """Get an authentication user by internal identifier."""
        row = (
            await self.db_session.execute(
                select(UserDB, OrganizationMembershipDB, OrganizationDB)
                .options(active_email_loader())
                .join(
                    OrganizationMembershipDB,
                    OrganizationMembershipDB.user_id == UserDB.id,
                )
                .join(
                    OrganizationDB,
                    OrganizationDB.id == OrganizationMembershipDB.organization_id,
                )
                .where(UserDB.id == user_id)
            )
        ).one_or_none()
        identity = to_identity(row) if row is not None else None
        return identity.user if identity is not None else None


def remaining_session_lifetime_seconds(
    session: SessionReadDTO, *, now: datetime | None = None
) -> int:
    """Return whole seconds before the effective SQL session expiration."""
    current_time = now or datetime.now(UTC)
    effective_expiry = min(session.expires_at, session.absolute_expires_at)
    return max(0, int((effective_expiry - current_time).total_seconds()))
