"""Current-user OAuth2 authorization inspection and revocation service."""

from datetime import datetime, UTC
from typing import cast, TYPE_CHECKING

from sqlalchemy import and_, delete, func, or_, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.time import as_utc_aware
from app.db.models.oauth2_client import OAuth2ClientDB
from app.db.models.oauth2_session import OAuth2SessionDB
from app.db.models.oauth2_token_pair import OAuth2TokenPairDB
from app.oauth2.public_ids import parse_oauth2_session_id
from app.oauth2.user_authorizations.dtos import (
    OAuth2AuthorizationDTO,
    OAuth2AuthorizationPageDTO,
)
from app.public_ids import PublicId
from app.security.dtos import UserPrincipalContext


if TYPE_CHECKING:
    from sqlalchemy.engine import CursorResult


class OAuth2AuthorizationService:
    """Inspect and revoke OAuth2 grants owned by the current user."""

    def __init__(
        self,
        *,
        db_session: AsyncSession,
    ) -> None:
        """Initialize the authorization service dependencies."""
        self.db_session = db_session

    async def list_authorizations(
        self,
        *,
        user_ctx: UserPrincipalContext,
        offset: int,
        limit: int,
    ) -> OAuth2AuthorizationPageDTO:
        """List active OAuth2 authorization sessions for the current user."""
        now = datetime.now(UTC)
        statement = (
            select(OAuth2TokenPairDB, OAuth2SessionDB, OAuth2ClientDB)
            .join(OAuth2SessionDB, OAuth2SessionDB.id == OAuth2TokenPairDB.session_id)
            .join(
                OAuth2ClientDB,
                OAuth2ClientDB.client_id == OAuth2SessionDB.client_id,
            )
            .where(OAuth2SessionDB.organization_id == user_ctx.organization_id)
            .where(OAuth2SessionDB.user_id == user_ctx.user_id)
            .where(OAuth2SessionDB.ended_at.is_(None))
            .where(
                or_(
                    OAuth2TokenPairDB.refresh_expires_at > now,
                    and_(
                        OAuth2TokenPairDB.refresh_expires_at.is_(None),
                        OAuth2TokenPairDB.access_expires_at > now,
                    ),
                )
            )
        )
        total = await self.db_session.scalar(
            select(func.count()).select_from(statement.subquery())
        )
        rows = (
            await self.db_session.execute(
                statement.order_by(
                    OAuth2TokenPairDB.created_at.desc(),
                    OAuth2TokenPairDB.session_id.desc(),
                )
                .offset(offset)
                .limit(limit)
            )
        ).all()
        authorizations: list[OAuth2AuthorizationDTO] = []
        for token_pair, oauth2_session, client in rows:
            authorizations.append(
                OAuth2AuthorizationDTO(
                    public_id=PublicId(oauth2_session.public_id),
                    client_id=client.client_id,
                    client_name=client.name,
                    client_active=client.is_active,
                    grant_type=oauth2_session.grant_type,
                    scopes=oauth2_session.scope.split(),
                    created_at=as_utc_aware(oauth2_session.created_at),
                    last_token_issued_at=as_utc_aware(token_pair.updated_at),
                )
            )
        return OAuth2AuthorizationPageDTO(
            items=authorizations,
            total=int(total or 0),
        )

    async def revoke_authorization(
        self,
        *,
        authorization_id: str,
        user_ctx: UserPrincipalContext,
    ) -> bool:
        """End one owned authorization session and delete its token state."""
        oauth2_session = await self.db_session.scalar(
            select(OAuth2SessionDB).where(
                OAuth2SessionDB.public_id == parse_oauth2_session_id(authorization_id)
            )
        )
        if (
            oauth2_session is None
            or oauth2_session.user_id != user_ctx.user_id
            or oauth2_session.ended_at is not None
        ):
            return False
        token_pair = await self.db_session.get(OAuth2TokenPairDB, oauth2_session.id)
        if (
            token_pair is None
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
                delete(OAuth2TokenPairDB).where(
                    OAuth2TokenPairDB.session_id == oauth2_session.id
                )
            ),
        )
        await self.db_session.flush()
        return bool(deleted.rowcount)
