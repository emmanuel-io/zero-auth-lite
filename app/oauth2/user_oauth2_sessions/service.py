"""Current-user OAuth2 session inspection and revocation service."""

from datetime import datetime, UTC
from typing import cast, TYPE_CHECKING
from uuid import UUID

from sqlalchemy import delete, func, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.time import as_utc_aware
from app.db.models.oauth2_client import OAuth2ClientDB
from app.db.models.oauth2_session import OAuth2SessionDB
from app.db.models.oauth2_token_state import OAuth2TokenStateDB
from app.oauth2.grants.types import OAuth2SessionGrantType
from app.oauth2.sessions.status import token_family_is_current_predicate
from app.oauth2.user_oauth2_sessions.dtos import (
    UserOAuth2SessionDTO,
    UserOAuth2SessionPageDTO,
)
from app.security.principals import UserPrincipalContext


if TYPE_CHECKING:
    from sqlalchemy.engine import CursorResult


class UserOAuth2SessionService:
    """Inspect and revoke OAuth2 sessions owned by the current user."""

    def __init__(
        self,
        *,
        db_session: AsyncSession,
    ) -> None:
        """Initialize the OAuth2 session service dependencies."""
        self.db_session = db_session

    async def list_sessions(
        self,
        *,
        user_ctx: UserPrincipalContext,
        offset: int,
        limit: int,
    ) -> UserOAuth2SessionPageDTO:
        """List active OAuth2 sessions for the current user."""
        now = datetime.now(UTC)
        statement = (
            select(OAuth2TokenStateDB, OAuth2SessionDB, OAuth2ClientDB)
            .join(OAuth2SessionDB, OAuth2SessionDB.id == OAuth2TokenStateDB.session_id)
            .join(
                OAuth2ClientDB,
                OAuth2ClientDB.client_id == OAuth2SessionDB.client_id,
            )
            .where(OAuth2SessionDB.organization_id == user_ctx.organization_id)
            .where(OAuth2SessionDB.user_id == user_ctx.user_id)
            .where(token_family_is_current_predicate(now=now))
        )
        total = await self.db_session.scalar(
            select(func.count()).select_from(statement.subquery())
        )
        rows = (
            await self.db_session.execute(
                statement.order_by(
                    OAuth2SessionDB.created_at.desc(),
                    OAuth2SessionDB.id.desc(),
                )
                .offset(offset)
                .limit(limit)
            )
        ).all()
        sessions: list[UserOAuth2SessionDTO] = []
        for token_state, oauth2_session, client in rows:
            sessions.append(
                UserOAuth2SessionDTO(
                    public_id=oauth2_session.public_id,
                    client_id=client.client_id,
                    client_name=client.name,
                    client_active=client.is_active,
                    grant_type=OAuth2SessionGrantType(oauth2_session.grant_type),
                    scopes=oauth2_session.scope.split(),
                    created_at=as_utc_aware(oauth2_session.created_at),
                    last_token_issued_at=as_utc_aware(token_state.updated_at),
                )
            )
        return UserOAuth2SessionPageDTO(
            items=sessions,
            total=int(total or 0),
        )

    async def revoke_session(
        self,
        *,
        session_id: UUID,
        user_ctx: UserPrincipalContext,
    ) -> bool:
        """End one owned OAuth2 session and delete its token state."""
        oauth2_session = await self.db_session.scalar(
            select(OAuth2SessionDB).where(OAuth2SessionDB.public_id == session_id)
        )
        if (
            oauth2_session is None
            or oauth2_session.user_id != user_ctx.user_id
            or oauth2_session.ended_at is not None
        ):
            return False
        token_state = await self.db_session.get(OAuth2TokenStateDB, oauth2_session.id)
        if (
            token_state is None
            or oauth2_session.organization_id != user_ctx.organization_id
        ):
            return False
        ended = cast(
            "CursorResult[object]",
            await self.db_session.execute(
                update(OAuth2SessionDB)
                .where(OAuth2SessionDB.id == oauth2_session.id)
                .where(OAuth2SessionDB.ended_at.is_(None))
                .values(ended_at=datetime.now(UTC))
            ),
        )
        if not ended.rowcount:
            return False
        deleted = cast(
            "CursorResult[object]",
            await self.db_session.execute(
                delete(OAuth2TokenStateDB).where(
                    OAuth2TokenStateDB.session_id == oauth2_session.id
                )
            ),
        )
        await self.db_session.flush()
        return bool(deleted.rowcount)
