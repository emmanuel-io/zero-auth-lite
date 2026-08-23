"""Transactional revocation for OAuth2 client policy changes."""

from datetime import datetime, UTC
from typing import cast, TYPE_CHECKING

from sqlalchemy import delete, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models.oauth2_session import OAuth2SessionDB
from app.db.models.oauth2_token_pair import OAuth2TokenPairDB


if TYPE_CHECKING:
    from sqlalchemy.engine import CursorResult


class OAuth2ClientSessionRevocationService:
    """End every token family issued to one OAuth2 client."""

    def __init__(self, *, db_session: AsyncSession) -> None:
        """Initialize the revocation boundary."""
        self.db_session = db_session

    async def persist(self, *, client_id: str) -> int:
        """Revoke a client's sessions and token pairs in the current transaction."""
        session_ids = (
            select(OAuth2SessionDB.id)
            .join(OAuth2TokenPairDB, OAuth2TokenPairDB.session_id == OAuth2SessionDB.id)
            .where(OAuth2SessionDB.client_id == client_id)
        )
        await self.db_session.execute(
            update(OAuth2SessionDB)
            .where(OAuth2SessionDB.id.in_(session_ids))
            .where(OAuth2SessionDB.ended_at.is_(None))
            .values(ended_at=datetime.now(UTC))
        )
        result = cast(
            "CursorResult[object]",
            await self.db_session.execute(
                delete(OAuth2TokenPairDB).where(
                    OAuth2TokenPairDB.session_id.in_(session_ids)
                )
            ),
        )
        await self.db_session.flush()
        return int(result.rowcount or 0)
