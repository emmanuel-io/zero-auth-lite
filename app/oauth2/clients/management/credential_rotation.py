"""Credential rotation for confidential global OAuth2 clients."""

from logging import getLogger
from typing import TYPE_CHECKING

from sqlalchemy import select, update

from app.db.models.oauth2_client import OAuth2ClientDB
from app.identity.public_ids import format_user_id
from app.oauth2.clients.credential_generation import generate_oauth2_client_secret
from app.oauth2.clients.dtos import OAuth2ClientReadDTO, OAuth2ClientSecretDTO
from app.oauth2.clients.management.authorization import require_operator
from app.oauth2.clients.management.errors import (
    InvalidOAuth2ClientPayloadError,
    OAuth2ClientAdminNotFoundError,
)
from app.oauth2.clients.management.policy import (
    ERR_PUBLIC_CLIENT_HAS_NO_SECRET,
)
from app.password.async_hashing import hash_password
from app.password.protocols import PasswordHasherProtocol
from app.security.dtos import UserPrincipalContext


if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import async_sessionmaker, AsyncSession


logger = getLogger(__name__)


class OAuth2ClientCredentialRotationService:
    """Rotate credentials for global confidential OAuth2 clients."""

    def __init__(
        self,
        *,
        session_factory: "async_sessionmaker[AsyncSession]",
        password_hasher: PasswordHasherProtocol,
    ) -> None:
        """Initialize client credential dependencies."""
        self.session_factory = session_factory
        self.password_hasher = password_hasher

    async def create_client_secret(
        self,
        *,
        client_id: str,
        operator_ctx: UserPrincipalContext,
    ) -> OAuth2ClientSecretDTO:
        """Create and return a confidential OAuth2 client's new secret."""
        require_operator(operator_ctx)
        async with self.session_factory() as read_session:
            row = await read_session.scalar(
                select(OAuth2ClientDB).where(OAuth2ClientDB.client_id == client_id)
            )
        existing = OAuth2ClientReadDTO.model_validate(row) if row is not None else None
        if existing is None:
            raise OAuth2ClientAdminNotFoundError
        if not existing.is_confidential:
            raise InvalidOAuth2ClientPayloadError(ERR_PUBLIC_CLIENT_HAS_NO_SECRET)

        raw_secret = generate_oauth2_client_secret()
        secret_hash = await hash_password(self.password_hasher, raw_secret)
        async with self.session_factory.begin() as write_session:
            updated_client_id = await write_session.scalar(
                update(OAuth2ClientDB)
                .where(OAuth2ClientDB.client_id == client_id)
                .where(OAuth2ClientDB.is_confidential.is_(True))
                .values(client_secret=secret_hash)
                .returning(OAuth2ClientDB.client_id)
            )
            if updated_client_id is None:
                raise OAuth2ClientAdminNotFoundError
        logger.info(
            (
                "event=oauth2_client_secret_rotated outcome=success client_id=%s "
                "subject_id=%s"
            ),
            client_id,
            format_user_id(operator_ctx.user_public_id)
            if operator_ctx.user_public_id
            else "unknown",
        )
        return OAuth2ClientSecretDTO(
            client_id=client_id,
            client_secret=raw_secret,
        )
