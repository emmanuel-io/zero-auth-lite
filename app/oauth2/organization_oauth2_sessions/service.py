"""Organization-scoped administration for OAuth2 sessions and token families."""

from datetime import datetime, UTC
from typing import cast, TYPE_CHECKING
from uuid import UUID

from fastapi import status
from sqlalchemy import and_, delete, func, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.errors.base import AppError
from app.core.errors.common import ForbiddenOperationError
from app.db.models.oauth2_session import OAuth2SessionDB
from app.db.models.oauth2_token_state import OAuth2TokenStateDB
from app.db.models.organization_membership import OrganizationMembershipDB
from app.db.models.user import UserDB
from app.oauth2.grants.types import OAuth2SessionGrantType
from app.oauth2.organization_oauth2_sessions.dtos import (
    OAuth2RevocationResultDTO,
    OrganizationOAuth2SessionDTO,
    OrganizationOAuth2SessionPageDTO,
)
from app.oauth2.sessions.mapping import to_oauth2_session_dto
from app.oauth2.sessions.status import (
    token_family_is_current,
    token_family_is_current_predicate,
)
from app.oauth2.tokens.dtos import OAuth2TokenStateReadDTO
from app.security.principals import UserPrincipalContext
from app.security.roles import Role


if TYPE_CHECKING:
    from sqlalchemy.engine import CursorResult


class OrganizationOAuth2SessionNotFoundError(AppError):
    """Raised when a session is absent from the authenticated organization."""

    code = "OAUTH2_SESSION_NOT_FOUND"
    message = "OAuth2 session not found in the authenticated organization."
    status = status.HTTP_404_NOT_FOUND


class OrganizationOAuth2SessionService:
    """Inspect and revoke organization-owned OAuth2 sessions and token families."""

    def __init__(
        self,
        *,
        db_session: AsyncSession,
    ) -> None:
        """Initialize organization-scoped OAuth2 session administration."""
        self.db_session = db_session

    @staticmethod
    def _require_organization_admin(actor_ctx: UserPrincipalContext) -> None:
        """Reject direct service use by a non-administrator principal."""
        if Role.ORGANIZATION_ADMIN not in actor_ctx.roles:
            raise ForbiddenOperationError

    async def list_sessions(  # noqa: PLR0913
        self,
        *,
        actor_ctx: UserPrincipalContext,
        client_id: UUID | None,
        grant_type: OAuth2SessionGrantType | None,
        user_public_id: UUID | None,
        active_only: bool,
        offset: int,
        limit: int,
    ) -> OrganizationOAuth2SessionPageDTO:
        """List OAuth2 token families and sessions for the current organization."""
        self._require_organization_admin(actor_ctx)
        now = datetime.now(UTC)
        internal_user_id: int | None = None
        if user_public_id is not None:
            user = await self.db_session.scalar(
                select(UserDB)
                .join(
                    OrganizationMembershipDB,
                    OrganizationMembershipDB.user_id == UserDB.id,
                )
                .where(UserDB.public_id == user_public_id)
                .where(
                    OrganizationMembershipDB.organization_id
                    == actor_ctx.organization_id
                )
            )
            if user is None:
                return OrganizationOAuth2SessionPageDTO(items=[], total=0)
            internal_user_id = user.id
        stmt = (
            select(OAuth2TokenStateDB, OAuth2SessionDB, UserDB.public_id)
            .join(OAuth2SessionDB, OAuth2SessionDB.id == OAuth2TokenStateDB.session_id)
            .outerjoin(
                OrganizationMembershipDB,
                and_(
                    OrganizationMembershipDB.user_id == OAuth2SessionDB.user_id,
                    OrganizationMembershipDB.organization_id
                    == actor_ctx.organization_id,
                ),
            )
            .outerjoin(UserDB, UserDB.id == OrganizationMembershipDB.user_id)
            .where(OAuth2SessionDB.organization_id == actor_ctx.organization_id)
        )
        if client_id is not None:
            stmt = stmt.where(OAuth2SessionDB.client_id == client_id)
        if grant_type is not None:
            stmt = stmt.where(OAuth2SessionDB.grant_type == grant_type)
        if internal_user_id is not None:
            stmt = stmt.where(OAuth2SessionDB.user_id == internal_user_id)
        if active_only:
            stmt = stmt.where(token_family_is_current_predicate(now=now))
        total = await self.db_session.scalar(
            select(func.count()).select_from(stmt.subquery())
        )
        rows = (
            await self.db_session.execute(
                stmt.order_by(
                    OAuth2SessionDB.created_at.desc(),
                    OAuth2SessionDB.id.desc(),
                )
                .offset(offset)
                .limit(limit)
            )
        ).all()
        sessions: list[OrganizationOAuth2SessionDTO] = []
        for token_row, session_row, row_user_public_id in rows:
            token_state = OAuth2TokenStateReadDTO.model_validate(token_row)
            session = to_oauth2_session_dto(session_row)
            public_user_id = (
                row_user_public_id if row_user_public_id is not None else None
            )
            sessions.append(
                OrganizationOAuth2SessionDTO(
                    public_id=session.public_id,
                    client_id=session.client_id,
                    grant_type=session.grant_type,
                    scopes=session.scope.split(),
                    user_public_id=public_user_id,
                    organization_public_id=actor_ctx.organization_public_id,
                    active=token_family_is_current(token_state, session),
                    access_expires_at=token_state.access_expires_at,
                    refresh_expires_at=token_state.refresh_expires_at,
                    created_at=session.created_at,
                    updated_at=token_state.updated_at,
                )
            )
        return OrganizationOAuth2SessionPageDTO(
            items=sessions,
            total=int(total or 0),
        )

    async def revoke_client_token_families(
        self,
        *,
        client_id: UUID,
        actor_ctx: UserPrincipalContext,
    ) -> OAuth2RevocationResultDTO:
        """Revoke a client's OAuth2 token families in the current organization."""
        self._require_organization_admin(actor_ctx)
        session_ids = (
            select(OAuth2SessionDB.id)
            .join(
                OAuth2TokenStateDB, OAuth2TokenStateDB.session_id == OAuth2SessionDB.id
            )
            .where(OAuth2SessionDB.organization_id == actor_ctx.organization_id)
            .where(OAuth2SessionDB.client_id == client_id)
        )
        ended = cast(
            "CursorResult[object]",
            await self.db_session.execute(
                update(OAuth2SessionDB)
                .where(OAuth2SessionDB.id.in_(session_ids))
                .where(OAuth2SessionDB.ended_at.is_(None))
                .values(ended_at=datetime.now(UTC))
            ),
        )
        deleted = cast(
            "CursorResult[object]",
            await self.db_session.execute(
                delete(OAuth2TokenStateDB).where(
                    OAuth2TokenStateDB.session_id.in_(session_ids)
                )
            ),
        )
        await self.db_session.flush()
        return OAuth2RevocationResultDTO(
            revoked_sessions=int(ended.rowcount or 0),
            revoked_token_states=int(deleted.rowcount or 0),
        )

    async def revoke_session(
        self,
        *,
        session_public_id: UUID,
        actor_ctx: UserPrincipalContext,
    ) -> OAuth2RevocationResultDTO:
        """Revoke one OAuth2 session by public session identifier."""
        self._require_organization_admin(actor_ctx)
        session_row = await self.db_session.scalar(
            select(OAuth2SessionDB).where(
                OAuth2SessionDB.public_id == session_public_id
            )
        )
        session = (
            to_oauth2_session_dto(session_row) if session_row is not None else None
        )
        if session is None:
            raise OrganizationOAuth2SessionNotFoundError
        token_row = await self.db_session.scalar(
            select(OAuth2TokenStateDB).where(
                OAuth2TokenStateDB.session_id == session.id
            )
        )
        token_state = (
            OAuth2TokenStateReadDTO.model_validate(token_row)
            if token_row is not None
            else None
        )
        if token_state is None or session.organization_id != actor_ctx.organization_id:
            raise OrganizationOAuth2SessionNotFoundError
        ended = cast(
            "CursorResult[object]",
            await self.db_session.execute(
                update(OAuth2SessionDB)
                .where(OAuth2SessionDB.id == session.id)
                .where(OAuth2SessionDB.ended_at.is_(None))
                .values(ended_at=datetime.now(UTC))
            ),
        )
        deleted = cast(
            "CursorResult[object]",
            await self.db_session.execute(
                delete(OAuth2TokenStateDB).where(
                    OAuth2TokenStateDB.session_id == session.id
                )
            ),
        )
        await self.db_session.flush()
        return OAuth2RevocationResultDTO(
            revoked_sessions=int(ended.rowcount or 0),
            revoked_token_states=int(deleted.rowcount or 0),
        )
