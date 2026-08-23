"""Registration service for global OAuth2 clients."""

from logging import getLogger
from typing import TYPE_CHECKING

from sqlalchemy import insert
from sqlalchemy.exc import IntegrityError

from app.db.models.oauth2_client import OAuth2ClientDB
from app.identity.public_ids import format_user_id
from app.oauth2.clients.credential_generation import (
    generate_oauth2_client_id,
    generate_oauth2_client_secret,
)
from app.oauth2.clients.dtos import (
    OAuth2ClientCreateResultDTO,
    OAuth2ClientPersistenceCreateDTO,
    OAuth2ClientReadDTO,
    OAuth2ClientRegistrationDTO,
)
from app.oauth2.clients.management.authorization import require_operator
from app.oauth2.clients.management.errors import OAuth2ClientConflictError
from app.oauth2.clients.management.policy import OAuth2ClientPolicy
from app.password.async_hashing import hash_password
from app.password.protocols import PasswordHasherProtocol
from app.security.dtos import UserPrincipalContext


if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession


logger = getLogger(__name__)


class OAuth2ClientRegistrationService:
    """Register global OAuth2 clients and issue initial credentials."""

    def __init__(
        self,
        *,
        db_session: "AsyncSession",
        policy: OAuth2ClientPolicy,
        password_hasher: PasswordHasherProtocol,
    ) -> None:
        """Initialize client registration dependencies."""
        self.db_session = db_session
        self.policy = policy
        self.password_hasher = password_hasher

    async def create_client(
        self,
        *,
        dto: OAuth2ClientRegistrationDTO,
        operator_ctx: UserPrincipalContext,
    ) -> OAuth2ClientCreateResultDTO:
        """Create a global OAuth2 client."""
        require_operator(operator_ctx)
        self.policy.validate(
            grant_types=dto.grant_types,
            redirect_uris=dto.redirect_uris or [],
            is_confidential=dto.is_confidential,
            requires_consent=dto.requires_consent,
        )
        raw_secret = generate_oauth2_client_secret() if dto.is_confidential else None
        try:
            data = OAuth2ClientPersistenceCreateDTO(
                client_id=generate_oauth2_client_id(),
                client_secret=(
                    await hash_password(self.password_hasher, raw_secret)
                    if raw_secret
                    else None
                ),
                **dto.model_dump(),
            )
            row = (
                await self.db_session.execute(
                    insert(OAuth2ClientDB)
                    .values(**data.model_dump())
                    .returning(OAuth2ClientDB)
                )
            ).scalar_one()
            await self.db_session.flush()
            client = OAuth2ClientReadDTO.model_validate(row)
        except IntegrityError as exc:
            raise OAuth2ClientConflictError from exc

        logger.info(
            (
                "event=oauth2_client_created outcome=attempted client_id=%s "
                "subject_id=%s confidential=%s active=%s grant_types=%s"
            ),
            client.client_id,
            format_user_id(operator_ctx.user_public_id)
            if operator_ctx.user_public_id
            else "unknown",
            client.is_confidential,
            client.is_active,
            ",".join(client.grant_types),
        )
        await self.db_session.flush()
        return OAuth2ClientCreateResultDTO(client=client, client_secret=raw_secret)
