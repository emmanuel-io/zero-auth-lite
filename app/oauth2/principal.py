"""OAuth2 bearer-principal resolution service."""

from datetime import datetime, UTC
from logging import getLogger

from cryptography.hazmat.primitives.asymmetric import ed25519
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models.oauth2_client import OAuth2ClientDB
from app.db.models.oauth2_session import OAuth2SessionDB
from app.db.models.oauth2_token_pair import OAuth2TokenPairDB
from app.enums import Role
from app.oauth2.clients.dtos import OAuth2ClientReadDTO
from app.oauth2.errors import OAuth2AccessTokenInvalidError, OAuth2SessionInvalidError
from app.oauth2.oidc.keys import OAuth2VerifyKey
from app.oauth2.session_mapping import to_oauth2_token_family_dto
from app.oauth2.settings import OAuth2Settings
from app.oauth2.tokens.dtos import OAuth2TokenFamilyReadDTO
from app.oauth2.tokens.hash import hash_oauth2_token
from app.oauth2.tokens.verification import verify_access_token
from app.oauth2.user_identity import load_eligible_oauth2_user_identity
from app.security.dtos import (
    OAuth2ClientPrincipalContext,
    OAuth2PrincipalContext,
    OAuth2UserPrincipalContext,
)


logger = getLogger(__name__)


class OAuth2BearerPrincipalService:
    """Resolve authenticated principals from OAuth2 bearer access tokens."""

    def __init__(
        self,
        *,
        db_session: AsyncSession,
        settings: OAuth2Settings,
    ) -> None:
        """Store the focused dependencies needed for bearer principal loading."""
        self.db_session = db_session
        self.settings = settings

    async def get_current_user_context(
        self,
        *,
        access_token: str,
        key: ed25519.Ed25519PublicKey | str | tuple[OAuth2VerifyKey, ...],
    ) -> OAuth2UserPrincipalContext:
        """Validate a JWT access token and resolve its DB-backed user context."""
        principal = await self.get_current_principal_context(
            access_token=access_token,
            key=key,
        )
        if not isinstance(principal, OAuth2UserPrincipalContext):
            raise OAuth2AccessTokenInvalidError
        return principal

    async def get_current_principal_context(
        self,
        *,
        access_token: str,
        key: ed25519.Ed25519PublicKey | str | tuple[OAuth2VerifyKey, ...],
    ) -> OAuth2PrincipalContext:
        """Validate a JWT access token and resolve its user or client principal."""
        try:
            token_payload = verify_access_token(
                token=access_token,
                jwt_issuer=self.settings.jwt_issuer,
                jwt_audience=self.settings.jwt_audience,
                key=key,
            )
        except OAuth2AccessTokenInvalidError as exc:
            logger.warning("Access token verification failed", exc_info=exc)
            raise OAuth2AccessTokenInvalidError from exc
        family = await self._read_valid_token_family(
            access_token=access_token,
            access_jti=token_payload.access_jti,
        )
        session = family.session
        token_pair = family.token_pair
        client = await self._read_active_client(client_id=session.client_id)

        scopes = frozenset(session.scope.split())
        if session.user_id is None:
            if not session.is_active():
                raise OAuth2SessionInvalidError
            return OAuth2ClientPrincipalContext(
                organization_id=session.organization_id,
                session_id=token_pair.session_id,
                client_id=client.client_id,
                scopes=scopes,
                machine_organization_access=client.machine_organization_access,
            )

        identity = await load_eligible_oauth2_user_identity(
            db_session=self.db_session,
            user_id=session.user_id,
            organization_id=session.organization_id,
        )
        if identity is None or not session.is_active():
            raise OAuth2SessionInvalidError
        user, organization_id = identity.user, identity.organization.id

        return OAuth2UserPrincipalContext(
            organization_id=organization_id,
            session_id=token_pair.session_id,
            user_id=user.id,
            user_public_id=user.public_id,
            organization_public_id=identity.organization.public_id,
            client_id=client.client_id,
            scopes=scopes,
            roles=frozenset(Role(role) for role in user.roles),
        )

    async def _read_valid_token_family(
        self,
        *,
        access_token: str,
        access_jti: str,
    ) -> OAuth2TokenFamilyReadDTO:
        """Load the stored token family and validate expiry and JTI binding."""
        token_hash = hash_oauth2_token(
            token=access_token,
            secret=self.settings.token_hash_secret.get_secret_value(),
        )
        row = (
            await self.db_session.execute(
                select(OAuth2SessionDB, OAuth2TokenPairDB)
                .join(
                    OAuth2TokenPairDB,
                    OAuth2TokenPairDB.session_id == OAuth2SessionDB.id,
                )
                .where(OAuth2TokenPairDB.access_token_hash == token_hash)
            )
        ).one_or_none()
        if row is None:
            raise OAuth2AccessTokenInvalidError
        family = to_oauth2_token_family_dto(*row)
        token_pair = family.token_pair
        if token_pair.access_expires_at <= datetime.now(UTC):
            raise OAuth2AccessTokenInvalidError
        if token_pair.access_jti != access_jti:
            raise OAuth2AccessTokenInvalidError
        return family

    async def _read_active_client(self, *, client_id: str) -> OAuth2ClientReadDTO:
        """Load the active OAuth2 client that owns a stored token family."""
        client_row = await self.db_session.scalar(
            select(OAuth2ClientDB).where(OAuth2ClientDB.client_id == client_id)
        )
        client = (
            OAuth2ClientReadDTO.model_validate(client_row)
            if client_row is not None
            else None
        )
        if client is None or not client.is_active:
            raise OAuth2AccessTokenInvalidError
        return client
