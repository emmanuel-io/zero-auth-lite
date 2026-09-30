"""Transactional revocation after security-sensitive user changes."""

from datetime import datetime, UTC
from logging import getLogger
from typing import cast, TYPE_CHECKING

from sqlalchemy import delete, func, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.browser_sessions.enums import BrowserSessionRevocationReason
from app.db.models.browser_session import BrowserSessionDB
from app.db.models.oauth2_session import OAuth2SessionDB
from app.db.models.oauth2_token_state import OAuth2TokenStateDB
from app.db.models.organization import OrganizationDB
from app.db.models.organization_membership import OrganizationMembershipDB
from app.db.models.user import UserDB


if TYPE_CHECKING:
    from sqlalchemy.engine import CursorResult


logger = getLogger(__name__)


class SecuritySessionRevocationService:
    """Revoke browser and OAuth2 sessions in one SQL transaction."""

    def __init__(self, *, db_session: AsyncSession) -> None:
        """Initialize the revocation boundary."""
        self.db_session = db_session

    async def revoke_user_security_sessions(
        self, *, user_id: int, browser_reason: BrowserSessionRevocationReason
    ) -> None:
        """Revoke all user session authority in the current transaction."""
        user_public_id = await self.db_session.scalar(
            select(UserDB.public_id).where(UserDB.id == user_id)
        )
        await self.db_session.execute(
            update(UserDB)
            .where(UserDB.id == user_id)
            .values(sessions_invalid_before=datetime.now(UTC))
        )
        oauth2_result = cast(
            "CursorResult[object]",
            await self.db_session.execute(
                update(OAuth2SessionDB)
                .where(OAuth2SessionDB.user_id == user_id)
                .where(OAuth2SessionDB.ended_at.is_(None))
                .values(ended_at=func.now())
            ),
        )
        token_result = cast(
            "CursorResult[object]",
            await self.db_session.execute(
                delete(OAuth2TokenStateDB).where(
                    OAuth2TokenStateDB.session_id.in_(
                        select(OAuth2SessionDB.id).where(
                            OAuth2SessionDB.user_id == user_id
                        )
                    )
                )
            ),
        )
        browser_result = cast(
            "CursorResult[object]",
            await self.db_session.execute(
                update(BrowserSessionDB)
                .where(BrowserSessionDB.user_id == user_id)
                .where(BrowserSessionDB.revoked_at.is_(None))
                .values(revoked_at=func.now(), revoked_reason=browser_reason)
            ),
        )
        await self.db_session.flush()
        logger.info(
            (
                "event=security_sessions_revoked outcome=attempted subject_id=%s "
                "reason=%s browser_sessions=%s oauth2_sessions=%s token_states=%s"
            ),
            str(user_public_id) if user_public_id is not None else "unknown",
            browser_reason,
            int(browser_result.rowcount or 0),
            int(oauth2_result.rowcount or 0),
            int(token_result.rowcount or 0),
        )

    async def revoke_organization_security_sessions(
        self,
        *,
        organization_id: int,
        browser_reason: BrowserSessionRevocationReason,
    ) -> None:
        """Revoke browser and OAuth2 sessions attributed to one organization."""
        revoked_at = datetime.now(UTC)
        organization_public_id = await self.db_session.scalar(
            select(OrganizationDB.public_id).where(OrganizationDB.id == organization_id)
        )
        organization_user_ids = select(OrganizationMembershipDB.user_id).where(
            OrganizationMembershipDB.organization_id == organization_id
        )
        await self.db_session.execute(
            update(UserDB)
            .where(UserDB.id.in_(organization_user_ids))
            .values(sessions_invalid_before=revoked_at)
        )
        await self.db_session.execute(
            update(BrowserSessionDB)
            .where(BrowserSessionDB.user_id.in_(organization_user_ids))
            .where(BrowserSessionDB.revoked_at.is_(None))
            .values(revoked_at=revoked_at, revoked_reason=browser_reason)
        )

        oauth2_session_ids = select(OAuth2SessionDB.id).where(
            OAuth2SessionDB.organization_id == organization_id
        )
        await self.db_session.execute(
            update(OAuth2SessionDB)
            .where(OAuth2SessionDB.id.in_(oauth2_session_ids))
            .where(OAuth2SessionDB.ended_at.is_(None))
            .values(ended_at=revoked_at)
        )
        await self.db_session.execute(
            delete(OAuth2TokenStateDB).where(
                OAuth2TokenStateDB.session_id.in_(oauth2_session_ids)
            )
        )
        await self.db_session.flush()
        logger.info(
            (
                "event=organization_security_sessions_revoked outcome=attempted "
                "organization_id=%s reason=%s"
            ),
            str(organization_public_id)
            if organization_public_id is not None
            else "unknown",
            browser_reason,
        )

    async def clear_organization_oauth2_sessions(self, *, organization_id: int) -> int:
        """Delete OAuth2 session families attributed to one organization."""
        result = cast(
            "CursorResult[object]",
            await self.db_session.execute(
                delete(OAuth2SessionDB).where(
                    OAuth2SessionDB.organization_id == organization_id
                )
            ),
        )
        await self.db_session.flush()
        return int(result.rowcount or 0)

    async def clear_user_oauth2_sessions(self, *, user_id: int) -> int:
        """Delete OAuth2 session families belonging to one user."""
        result = cast(
            "CursorResult[object]",
            await self.db_session.execute(
                delete(OAuth2SessionDB).where(OAuth2SessionDB.user_id == user_id)
            ),
        )
        await self.db_session.flush()
        return int(result.rowcount or 0)

    async def clear_all_oauth2_sessions(self) -> int:
        """Delete every retained OAuth2 session family and its token state."""
        result = cast(
            "CursorResult[object]",
            await self.db_session.execute(delete(OAuth2SessionDB)),
        )
        await self.db_session.flush()
        return int(result.rowcount or 0)

    async def revoke_all_security_sessions(
        self, *, browser_reason: BrowserSessionRevocationReason
    ) -> None:
        """Revoke all browser and OAuth2 session authority on the server."""
        revoked_at = datetime.now(UTC)
        await self.db_session.execute(
            update(UserDB).values(sessions_invalid_before=revoked_at)
        )
        await self.db_session.execute(
            update(BrowserSessionDB)
            .where(BrowserSessionDB.revoked_at.is_(None))
            .values(revoked_at=revoked_at, revoked_reason=browser_reason)
        )
        await self.db_session.execute(
            update(OAuth2SessionDB)
            .where(OAuth2SessionDB.ended_at.is_(None))
            .values(ended_at=revoked_at)
        )
        await self.db_session.execute(delete(OAuth2TokenStateDB))
        await self.db_session.flush()
        logger.info(
            "event=server_security_sessions_revoked outcome=attempted reason=%s",
            browser_reason,
        )
