"""OAuth2 token revocation service."""

from dataclasses import dataclass
from datetime import datetime, UTC
from typing import Annotated
from uuid import UUID

from fastapi import Depends
from sqlalchemy import delete, or_, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.dependencies import DbSessionDep
from app.db.models.oauth2_session import OAuth2SessionDB
from app.db.models.oauth2_token_state import OAuth2TokenStateDB
from app.oauth2.grants.types import OAuth2SessionGrantType
from app.oauth2.settings import OAuth2Settings
from app.oauth2.tokens.hash import hash_oauth2_token
from app.settings.dependencies import OAuth2SettingsDep


@dataclass(frozen=True, slots=True)
class RevokedTokenFamily:
    """Metadata for a token family removed by revocation."""

    session_id: int
    session_public_id: UUID
    grant_type: OAuth2SessionGrantType


class TokenRevocationService:
    """Revoke client-owned token state without revealing token validity."""

    def __init__(self, db_session: AsyncSession, settings: OAuth2Settings) -> None:
        """Initialize revocation with database and hashing settings."""
        self.db_session = db_session
        self.settings = settings

    async def revoke(
        self, *, token: str, client_id: UUID, token_type_hint: str | None
    ) -> RevokedTokenFamily | None:
        """Delete matching token state and end its OAuth2 session."""
        _ = token_type_hint
        token_hash = hash_oauth2_token(
            token=token, secret=self.settings.token_hash_secret.get_secret_value()
        )
        row = (
            await self.db_session.execute(
                select(OAuth2SessionDB, OAuth2TokenStateDB)
                .join(
                    OAuth2TokenStateDB,
                    OAuth2TokenStateDB.session_id == OAuth2SessionDB.id,
                )
                .where(
                    or_(
                        OAuth2TokenStateDB.access_token_hash == token_hash,
                        OAuth2TokenStateDB.refresh_token_hash == token_hash,
                    )
                )
            )
        ).one_or_none()
        if row is None:
            return None
        oauth2_session, token_state = row
        if oauth2_session.client_id != client_id:
            return None
        metadata = RevokedTokenFamily(
            session_id=token_state.session_id,
            session_public_id=oauth2_session.public_id,
            grant_type=OAuth2SessionGrantType(oauth2_session.grant_type),
        )
        await self.db_session.execute(
            delete(OAuth2TokenStateDB).where(
                OAuth2TokenStateDB.session_id == token_state.session_id
            )
        )
        await self.db_session.execute(
            update(OAuth2SessionDB)
            .where(OAuth2SessionDB.id == token_state.session_id)
            .where(OAuth2SessionDB.ended_at.is_(None))
            .values(ended_at=datetime.now(UTC))
        )
        await self.db_session.flush()
        return metadata


def get_token_revocation_service(
    db_session: DbSessionDep, settings: OAuth2SettingsDep
) -> TokenRevocationService:
    """Provide token revocation behavior."""
    return TokenRevocationService(db_session, settings)


TokenRevocationServiceDep = Annotated[
    TokenRevocationService,
    Depends(get_token_revocation_service),
]
