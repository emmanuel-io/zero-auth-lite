"""Opaque identifiers for server-side OAuth2 authorization transactions."""

import secrets
from datetime import datetime, UTC
from typing import Annotated

from fastapi import Depends
from sqlalchemy import and_, insert, or_, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.dependencies import DbSessionDep
from app.db.models.oauth2_authorization_transaction import (
    OAuth2AuthorizationTransactionDB,
)
from app.oauth2.authorization.transaction_dtos import (
    AuthorizationTransactionCreateDTO,
    AuthorizationTransactionReadDTO,
)
from app.oauth2.specs import OAuth2Specs
from app.oauth2.tokens.hash import hash_oauth2_token


def create_authorization_transaction_id() -> str:
    """Create an unpredictable browser authorization transaction handle."""
    return secrets.token_urlsafe(OAuth2Specs.TRANSACTION_TOKEN_BYTES)


def hash_authorization_transaction_id(*, transaction_id: str, secret: str) -> str:
    """Hash a browser transaction handle for persistence and lookup."""
    return hash_oauth2_token(token=transaction_id, secret=secret)


class AuthorizationTransactionService:
    """Persist and atomically transition browser authorization interactions."""

    def __init__(self, db_session: AsyncSession) -> None:
        """Initialize the service with the request-owned database session."""
        self.db_session = db_session

    async def create(
        self, *, data: AuthorizationTransactionCreateDTO
    ) -> AuthorizationTransactionReadDTO:
        """Create one pending browser authorization transaction."""
        row = (
            await self.db_session.execute(
                insert(OAuth2AuthorizationTransactionDB)
                .values(**data.model_dump())
                .returning(OAuth2AuthorizationTransactionDB)
            )
        ).scalar_one()
        await self.db_session.flush()
        return AuthorizationTransactionReadDTO.model_validate(row)

    async def consume(
        self, *, transaction_hash: str, user_id: int, organization_id: int
    ) -> AuthorizationTransactionReadDTO | None:
        """Atomically consume one live transaction bound to a user."""
        now = datetime.now(UTC)
        row = await self.db_session.scalar(
            update(OAuth2AuthorizationTransactionDB)
            .where(
                OAuth2AuthorizationTransactionDB.transaction_hash == transaction_hash
            )
            .where(OAuth2AuthorizationTransactionDB.user_id == user_id)
            .where(OAuth2AuthorizationTransactionDB.organization_id == organization_id)
            .where(OAuth2AuthorizationTransactionDB.expires_at > now)
            .where(OAuth2AuthorizationTransactionDB.used_at.is_(None))
            .values(used_at=now)
            .returning(OAuth2AuthorizationTransactionDB)
        )
        await self.db_session.flush()
        return AuthorizationTransactionReadDTO.model_validate(row) if row else None

    async def bind_to_user(
        self, *, transaction_hash: str, user_id: int, organization_id: int
    ) -> AuthorizationTransactionReadDTO | None:
        """Atomically bind one live transaction to a browser user."""
        now = datetime.now(UTC)
        row = await self.db_session.scalar(
            update(OAuth2AuthorizationTransactionDB)
            .where(
                OAuth2AuthorizationTransactionDB.transaction_hash == transaction_hash
            )
            .where(OAuth2AuthorizationTransactionDB.expires_at > now)
            .where(OAuth2AuthorizationTransactionDB.used_at.is_(None))
            .where(
                or_(
                    and_(
                        OAuth2AuthorizationTransactionDB.user_id.is_(None),
                        OAuth2AuthorizationTransactionDB.organization_id.is_(None),
                    ),
                    and_(
                        OAuth2AuthorizationTransactionDB.user_id == user_id,
                        OAuth2AuthorizationTransactionDB.organization_id
                        == organization_id,
                    ),
                )
            )
            .values(user_id=user_id, organization_id=organization_id)
            .returning(OAuth2AuthorizationTransactionDB)
        )
        await self.db_session.flush()
        return AuthorizationTransactionReadDTO.model_validate(row) if row else None


def get_authorization_transaction_service(
    db_session: DbSessionDep,
) -> AuthorizationTransactionService:
    """Provide authorization-transaction persistence behavior."""
    return AuthorizationTransactionService(db_session)


AuthorizationTransactionServiceDep = Annotated[
    AuthorizationTransactionService,
    Depends(get_authorization_transaction_service),
]
