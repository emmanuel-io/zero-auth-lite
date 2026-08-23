"""Organization-scoped administration for OAuth2 sessions and token families."""

from datetime import datetime, UTC
from typing import cast, TYPE_CHECKING

from fastapi import status
from sqlalchemy import and_, delete, func, or_, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.errors.base import AppError
from app.db.models.oauth2_session import OAuth2SessionDB
from app.db.models.oauth2_token_pair import OAuth2TokenPairDB
from app.db.models.organization_membership import OrganizationMembershipDB
from app.db.models.user import UserDB
from app.enums import Role
from app.errors import ForbiddenOperationError
from app.oauth2.organization_oauth2_session_dtos import (
    OAuth2RevocationResultDTO,
    OrganizationOAuth2SessionDTO,
    OrganizationOAuth2SessionPageDTO,
)
from app.oauth2.session_mapping import to_oauth2_session_dto
from app.oauth2.session_status import token_family_is_active
from app.oauth2.tokens.dtos import TokenPairReadDTO
from app.public_ids import PublicId
from app.security.dtos import UserPrincipalContext


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
        admin_ctx: UserPrincipalContext,
        client_id: str | None,
        grant_type: str | None,
        user_public_id: PublicId | None,
        active_only: bool,
        offset: int,
        limit: int,
    ) -> OrganizationOAuth2SessionPageDTO:
        """List OAuth2 token families and sessions for the current organization."""
        self._require_organization_admin(admin_ctx)
        if admin_ctx.organization_public_id is None:
            msg = "OAuth2 administration requires a public organization identifier."
            raise RuntimeError(msg)
        now = datetime.now(UTC)
        internal_user_id: int | None = None
        if user_public_id is not None:
            user = await self.db_session.scalar(
                select(UserDB)
                .join(
                    OrganizationMembershipDB,
                    OrganizationMembershipDB.user_id == UserDB.id,
                )
                .where(UserDB.public_id == int(user_public_id))
                .where(
                    OrganizationMembershipDB.organization_id
                    == admin_ctx.organization_id
                )
            )
            if user is None:
                return OrganizationOAuth2SessionPageDTO(items=[], total=0)
            internal_user_id = user.id
        stmt = (
            select(OAuth2TokenPairDB, OAuth2SessionDB, UserDB.public_id)
            .join(OAuth2SessionDB, OAuth2SessionDB.id == OAuth2TokenPairDB.session_id)
            .outerjoin(
                OrganizationMembershipDB,
                and_(
                    OrganizationMembershipDB.user_id == OAuth2SessionDB.user_id,
                    OrganizationMembershipDB.organization_id
                    == admin_ctx.organization_id,
                ),
            )
            .outerjoin(UserDB, UserDB.id == OrganizationMembershipDB.user_id)
            .where(OAuth2SessionDB.organization_id == admin_ctx.organization_id)
        )
        if client_id is not None:
            stmt = stmt.where(OAuth2SessionDB.client_id == client_id)
        if grant_type is not None:
            stmt = stmt.where(OAuth2SessionDB.grant_type == grant_type)
        if internal_user_id is not None:
            stmt = stmt.where(OAuth2SessionDB.user_id == internal_user_id)
        if active_only:
            stmt = stmt.where(OAuth2SessionDB.ended_at.is_(None)).where(
                or_(
                    OAuth2TokenPairDB.refresh_expires_at > now,
                    and_(
                        OAuth2TokenPairDB.refresh_expires_at.is_(None),
                        OAuth2TokenPairDB.access_expires_at > now,
                    ),
                )
            )
        total = await self.db_session.scalar(
            select(func.count()).select_from(stmt.subquery())
        )
        rows = (
            await self.db_session.execute(
                stmt.order_by(
                    OAuth2TokenPairDB.created_at.desc(),
                    OAuth2TokenPairDB.session_id.desc(),
                )
                .offset(offset)
                .limit(limit)
            )
        ).all()
        sessions: list[OrganizationOAuth2SessionDTO] = []
        for token_row, session_row, row_user_public_id in rows:
            token_pair = TokenPairReadDTO.model_validate(token_row)
            session = to_oauth2_session_dto(session_row)
            public_user_id = (
                PublicId(row_user_public_id) if row_user_public_id is not None else None
            )
            sessions.append(
                OrganizationOAuth2SessionDTO(
                    public_id=session.public_id,
                    client_id=session.client_id,
                    grant_type=session.grant_type,
                    scope=session.scope,
                    user_public_id=public_user_id,
                    organization_public_id=admin_ctx.organization_public_id,
                    active=token_family_is_active(token_pair, session),
                    access_expires_at=token_pair.access_expires_at,
                    refresh_expires_at=token_pair.refresh_expires_at,
                    created_at=session.created_at,
                    updated_at=token_pair.updated_at,
                )
            )
        return OrganizationOAuth2SessionPageDTO(
            items=sessions,
            total=int(total or 0),
        )

    async def revoke_client_token_families(
        self,
        *,
        client_id: str,
        admin_ctx: UserPrincipalContext,
    ) -> OAuth2RevocationResultDTO:
        """Revoke a client's OAuth2 token families in the current organization."""
        self._require_organization_admin(admin_ctx)
        session_ids = (
            select(OAuth2SessionDB.id)
            .join(OAuth2TokenPairDB, OAuth2TokenPairDB.session_id == OAuth2SessionDB.id)
            .where(OAuth2SessionDB.organization_id == admin_ctx.organization_id)
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
                delete(OAuth2TokenPairDB).where(
                    OAuth2TokenPairDB.session_id.in_(session_ids)
                )
            ),
        )
        await self.db_session.flush()
        return OAuth2RevocationResultDTO(
            revoked_sessions=int(ended.rowcount or 0),
            revoked_token_pairs=int(deleted.rowcount or 0),
        )

    async def revoke_session(
        self,
        *,
        session_public_id: PublicId,
        admin_ctx: UserPrincipalContext,
    ) -> OAuth2RevocationResultDTO:
        """Revoke one OAuth2 session by public session identifier."""
        self._require_organization_admin(admin_ctx)
        session_row = await self.db_session.scalar(
            select(OAuth2SessionDB).where(
                OAuth2SessionDB.public_id == int(session_public_id)
            )
        )
        session = (
            to_oauth2_session_dto(session_row) if session_row is not None else None
        )
        if session is None:
            raise OrganizationOAuth2SessionNotFoundError
        token_row = await self.db_session.scalar(
            select(OAuth2TokenPairDB).where(OAuth2TokenPairDB.session_id == session.id)
        )
        token_pair = (
            TokenPairReadDTO.model_validate(token_row)
            if token_row is not None
            else None
        )
        if token_pair is None or session.organization_id != admin_ctx.organization_id:
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
                delete(OAuth2TokenPairDB).where(
                    OAuth2TokenPairDB.session_id == session.id
                )
            ),
        )
        await self.db_session.flush()
        return OAuth2RevocationResultDTO(
            revoked_sessions=int(ended.rowcount or 0),
            revoked_token_pairs=int(deleted.rowcount or 0),
        )
