"""TokenIntrospectionService OAuth2 flow implementation."""

from datetime import datetime, UTC

from cryptography.hazmat.primitives.asymmetric import ed25519
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models.oauth2_client import OAuth2ClientDB
from app.db.models.oauth2_session import OAuth2SessionDB
from app.db.models.oauth2_token_pair import OAuth2TokenPairDB
from app.oauth2.clients.dtos import OAuth2ClientReadDTO
from app.oauth2.errors import OAuth2AccessTokenInvalidError
from app.oauth2.oidc.keys import OAuth2VerifyKey
from app.oauth2.schemas import TokenIntrospectionResponse
from app.oauth2.session_mapping import to_oauth2_token_family_dto
from app.oauth2.settings import OAuth2Settings
from app.oauth2.tokens.dtos import OAuth2TokenFamilyReadDTO
from app.oauth2.tokens.hash import hash_oauth2_token
from app.oauth2.tokens.verification import verify_access_token
from app.oauth2.user_identity import load_eligible_oauth2_user_identity


class TokenIntrospectionService:
    """Implement the introspection OAuth2 flow."""

    def __init__(
        self,
        *,
        db_session: AsyncSession,
        settings: OAuth2Settings,
    ) -> None:
        """Store the dependencies required for token introspection."""
        self.db_session = db_session
        self.settings = settings

    async def introspect_token(  # noqa: PLR0911
        self,
        *,
        token: str,
        client_id: str,
        key: ed25519.Ed25519PublicKey | str | tuple[OAuth2VerifyKey, ...],
    ) -> TokenIntrospectionResponse:
        """Inspect a token for the authenticated OAuth2 client.

        Args:
            token (str): Raw access or refresh token.
            client_id (str): Authenticated OAuth2 client identifier.
            key (ed25519.Ed25519PublicKey | str): Key used to verify access JWTs.

        Returns:
            TokenIntrospectionResponse: RFC 7662-style introspection response.
        """
        now = datetime.now(UTC)
        token_hash = hash_oauth2_token(
            token=token, secret=self.settings.token_hash_secret.get_secret_value()
        )
        access_row = (
            await self.db_session.execute(
                select(OAuth2SessionDB, OAuth2TokenPairDB)
                .join(
                    OAuth2TokenPairDB,
                    OAuth2TokenPairDB.session_id == OAuth2SessionDB.id,
                )
                .where(OAuth2TokenPairDB.access_token_hash == token_hash)
            )
        ).one_or_none()
        access_family = (
            to_oauth2_token_family_dto(*access_row) if access_row is not None else None
        )
        if access_family is not None:
            access_pair = access_family.token_pair
            if access_family.session.client_id != client_id:
                return TokenIntrospectionResponse(active=False)
            if not await self._token_family_principal_is_active(access_family):
                return TokenIntrospectionResponse(active=False)
            try:
                token_payload = verify_access_token(
                    token=token,
                    jwt_issuer=self.settings.jwt_issuer,
                    jwt_audience=self.settings.jwt_audience,
                    key=key,
                )
            except OAuth2AccessTokenInvalidError:
                return TokenIntrospectionResponse(active=False)

            if access_pair.access_expires_at <= now:
                return TokenIntrospectionResponse(active=False)
            if access_pair.access_jti != token_payload.access_jti:
                return TokenIntrospectionResponse(active=False)

            return TokenIntrospectionResponse(
                active=True,
                scope=token_payload.scope,
                client_id=token_payload.client_id,
                token_type="bearer",  # noqa: S106
                exp=int(access_pair.access_expires_at.timestamp()),
                sub=token_payload.subject,
                aud=token_payload.audience,
                iss=self.settings.jwt_issuer,
                jti=token_payload.access_jti,
            )

        refresh_row = (
            await self.db_session.execute(
                select(OAuth2SessionDB, OAuth2TokenPairDB)
                .join(
                    OAuth2TokenPairDB,
                    OAuth2TokenPairDB.session_id == OAuth2SessionDB.id,
                )
                .where(OAuth2TokenPairDB.refresh_token_hash == token_hash)
            )
        ).one_or_none()
        refresh_family = (
            to_oauth2_token_family_dto(*refresh_row)
            if refresh_row is not None
            else None
        )
        if refresh_family is None or refresh_family.session.client_id != client_id:
            return TokenIntrospectionResponse(active=False)
        refresh_pair = refresh_family.token_pair
        if not await self._token_family_principal_is_active(refresh_family):
            return TokenIntrospectionResponse(active=False)
        if refresh_pair.refresh_expires_at is None:
            return TokenIntrospectionResponse(active=False)
        if refresh_pair.refresh_expires_at <= now:
            return TokenIntrospectionResponse(active=False)
        return TokenIntrospectionResponse(
            active=True,
            scope=refresh_family.session.scope,
            client_id=refresh_family.session.client_id,
            token_type="bearer",  # noqa: S106
            exp=int(refresh_pair.refresh_expires_at.timestamp()),
        )

    async def _token_family_principal_is_active(
        self, family: OAuth2TokenFamilyReadDTO
    ) -> bool:
        """Return whether a stored token pair still belongs to live principals.

        Args:
            family (OAuth2TokenFamilyReadDTO): Joined family metadata and tokens.

        Returns:
            bool: True when the session, client, and user are still usable.
        """
        session = family.session
        if not session.is_active():
            return False
        client_row = await self.db_session.scalar(
            select(OAuth2ClientDB).where(OAuth2ClientDB.client_id == session.client_id)
        )
        client = (
            OAuth2ClientReadDTO.model_validate(client_row)
            if client_row is not None
            else None
        )
        if client is None or not client.is_active:
            return False
        if session.user_id is None:
            return True

        identity = await load_eligible_oauth2_user_identity(
            db_session=self.db_session,
            user_id=session.user_id,
            organization_id=session.organization_id,
        )
        return identity is not None
