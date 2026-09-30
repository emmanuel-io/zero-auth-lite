"""Credential rotation for confidential global OAuth2 clients."""

from logging import getLogger
from typing import TYPE_CHECKING
from uuid import UUID

from sqlalchemy import select, update

from app.db.models.oauth2_client import OAuth2ClientDB
from app.oauth2.clients.credential_generation import generate_oauth2_client_secret
from app.oauth2.clients.dtos import OAuth2ClientReadDTO, OAuth2ClientSecretDTO
from app.oauth2.clients.management.authorization import require_operator
from app.oauth2.clients.management.errors import (
    InvalidOAuth2ClientPayloadError,
    OAuth2ClientConflictError,
    OAuth2ClientManagementErrorReason,
    OAuth2ClientManagementNotFoundError,
)
from app.password.async_hashing import hash_password
from app.password.protocols import PasswordHasherProtocol
from app.security.principals import UserPrincipalContext


if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import async_sessionmaker, AsyncSession


logger = getLogger(__name__)


class OAuth2ClientCredentialRotationService:
    """Rotate credentials for global confidential OAuth2 clients."""

    def __init__(
        self,
        *,
        db_session: "AsyncSession",
        session_factory: "async_sessionmaker[AsyncSession]",
        password_hasher: PasswordHasherProtocol,
    ) -> None:
        """Initialize client credential dependencies."""
        self.db_session = db_session
        self.session_factory = session_factory
        self.password_hasher = password_hasher

    async def rotate_client_secret_autonomously(
        self,
        *,
        client_id: UUID,
        operator_ctx: UserPrincipalContext,
    ) -> OAuth2ClientSecretDTO:
        """Rotate a client secret outside the request-scoped transaction."""
        require_operator(operator_ctx)
        row = await self.db_session.scalar(
            select(OAuth2ClientDB).where(OAuth2ClientDB.client_id == client_id)
        )
        existing = OAuth2ClientReadDTO.model_validate(row) if row is not None else None
        if existing is None:
            raise OAuth2ClientManagementNotFoundError
        if not existing.is_confidential:
            raise InvalidOAuth2ClientPayloadError(
                OAuth2ClientManagementErrorReason.PUBLIC_CLIENT_HAS_NO_SECRET
            )

        # Discard incidental request-scoped writes and release SQLite's writer
        # lock before hashing and opening the autonomous rotation transaction.
        await self.db_session.rollback()
        raw_secret = generate_oauth2_client_secret()
        secret_hash = await hash_password(self.password_hasher, raw_secret)
        async with self.session_factory.begin() as write_session:
            updated_client_id = await write_session.scalar(
                update(OAuth2ClientDB)
                .where(OAuth2ClientDB.client_id == client_id)
                .where(OAuth2ClientDB.is_confidential.is_(True))
                .where(OAuth2ClientDB.client_secret == existing.client_secret)
                .values(client_secret=secret_hash)
                .returning(OAuth2ClientDB.client_id)
            )
            if updated_client_id is None:
                raise OAuth2ClientConflictError
        logger.info(
            (
                "event=oauth2_client_secret_rotated outcome=success client_id=%s "
                "subject_id=%s"
            ),
            client_id,
            str(operator_ctx.user_public_id)
            if operator_ctx.user_public_id
            else "unknown",
        )
        return OAuth2ClientSecretDTO(
            client_id=client_id,
            client_secret=raw_secret,
        )
