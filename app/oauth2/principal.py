"""OAuth2 bearer-principal resolution service."""

from datetime import datetime, UTC
from uuid import UUID

from cryptography.hazmat.primitives.asymmetric import ed25519
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models.oauth2_client import OAuth2ClientDB
from app.db.models.oauth2_session import OAuth2SessionDB
from app.db.models.oauth2_token_state import OAuth2TokenStateDB
from app.oauth2.clients.dtos import OAuth2ClientReadDTO
from app.oauth2.errors import (
    OAuth2AccessTokenInvalidError,
    OAuth2TokenSessionInvalidError,
)
from app.oauth2.principal_types import PrincipalType, session_principal_type
from app.oauth2.sessions.mapping import to_oauth2_token_family_dto
from app.oauth2.settings import OAuth2Settings
from app.oauth2.signing.keys import OAuth2VerifyKey
from app.oauth2.tokens.dtos import OAuth2TokenFamilyReadDTO
from app.oauth2.tokens.hash import hash_oauth2_token
from app.oauth2.tokens.verification import verify_access_token
from app.oauth2.user_identity import load_eligible_oauth2_user_identity
from app.security.principals import (
    OAuth2ClientPrincipalContext,
    OAuth2PrincipalContext,
    OAuth2UserPrincipalContext,
)
from app.security.roles import Role


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
        principal = await self.get_current_oauth2_principal_context(
            access_token=access_token,
            key=key,
        )
        if not isinstance(principal, OAuth2UserPrincipalContext):
            raise OAuth2AccessTokenInvalidError
        return principal

    async def get_current_oauth2_principal_context(
        self,
        *,
        access_token: str,
        key: ed25519.Ed25519PublicKey | str | tuple[OAuth2VerifyKey, ...],
    ) -> OAuth2PrincipalContext:
        """Validate a JWT access token and resolve its user or client principal."""
        token_payload = verify_access_token(
            token=access_token,
            issuer=self.settings.issuer,
            access_token_audience=self.settings.access_token_audience,
            key=key,
        )
        family = await self._read_valid_token_family(
            access_token=access_token,
            access_jti=token_payload.access_jti,
        )
        session = family.session
        token_state = family.token_state
        client = await self._read_active_client(client_id=session.client_id)

        try:
            principal_type = session_principal_type(
                grant_type=session.grant_type,
                user_id=session.user_id,
                organization_id=session.organization_id,
            )
        except ValueError as exc:
            raise OAuth2TokenSessionInvalidError from exc
        if token_payload.client_id != session.client_id:
            raise OAuth2TokenSessionInvalidError

        scopes = frozenset(session.scope.split())
        if principal_type is PrincipalType.CLIENT:
            if (
                not session.is_active()
                or token_payload.principal_type is not PrincipalType.CLIENT
                or token_payload.subject != str(session.client_id)
                or token_payload.organization is not None
            ):
                raise OAuth2TokenSessionInvalidError
            return OAuth2ClientPrincipalContext(
                organization_id=session.organization_id,
                oauth2_session_id=token_state.session_id,
                client_id=client.client_id,
                scopes=scopes,
            )

        identity = await load_eligible_oauth2_user_identity(
            db_session=self.db_session,
            user_id=session.user_id,
            organization_id=session.organization_id,
        )
        if (
            identity is None
            or not session.is_active()
            or token_payload.principal_type not in {None, PrincipalType.USER}
        ):
            raise OAuth2TokenSessionInvalidError
        user, organization_id = identity.user, identity.organization.id
        if token_payload.subject != str(
            user.public_id
        ) or token_payload.organization != str(identity.organization.public_id):
            raise OAuth2TokenSessionInvalidError

        return OAuth2UserPrincipalContext(
            organization_id=organization_id,
            oauth2_session_id=token_state.session_id,
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
                select(OAuth2SessionDB, OAuth2TokenStateDB)
                .join(
                    OAuth2TokenStateDB,
                    OAuth2TokenStateDB.session_id == OAuth2SessionDB.id,
                )
                .where(OAuth2TokenStateDB.access_token_hash == token_hash)
            )
        ).one_or_none()
        if row is None:
            raise OAuth2AccessTokenInvalidError
        family = to_oauth2_token_family_dto(*row)
        token_state = family.token_state
        if token_state.access_expires_at <= datetime.now(UTC):
            raise OAuth2AccessTokenInvalidError
        if token_state.access_jti != access_jti:
            raise OAuth2AccessTokenInvalidError
        return family

    async def _read_active_client(self, *, client_id: UUID) -> OAuth2ClientReadDTO:
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
