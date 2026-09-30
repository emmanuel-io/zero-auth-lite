"""TokenIntrospectionService OAuth2 flow implementation."""

from datetime import datetime, UTC
from uuid import UUID

from cryptography.hazmat.primitives.asymmetric import ed25519
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models.oauth2_client import OAuth2ClientDB
from app.db.models.oauth2_session import OAuth2SessionDB
from app.db.models.oauth2_token_state import OAuth2TokenStateDB
from app.identity.dtos import IdentityDTO
from app.oauth2.clients.dtos import OAuth2ClientReadDTO
from app.oauth2.errors import OAuth2AccessTokenInvalidError
from app.oauth2.principal_types import PrincipalType, session_principal_type
from app.oauth2.schemas import TokenIntrospectionResponse
from app.oauth2.sessions.mapping import to_oauth2_token_family_dto
from app.oauth2.settings import OAuth2Settings
from app.oauth2.signing.keys import OAuth2VerifyKey
from app.oauth2.tokens.access import AccessTokenPayload
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
        client_id: UUID,
        key: ed25519.Ed25519PublicKey | str | tuple[OAuth2VerifyKey, ...],
    ) -> TokenIntrospectionResponse:
        """Return an RFC 7662 view for the authenticated OAuth2 client."""
        now = datetime.now(UTC)
        token_hash = hash_oauth2_token(
            token=token, secret=self.settings.token_hash_secret.get_secret_value()
        )
        access_row = (
            await self.db_session.execute(
                select(OAuth2SessionDB, OAuth2TokenStateDB)
                .join(
                    OAuth2TokenStateDB,
                    OAuth2TokenStateDB.session_id == OAuth2SessionDB.id,
                )
                .where(OAuth2TokenStateDB.access_token_hash == token_hash)
            )
        ).one_or_none()
        access_family = (
            to_oauth2_token_family_dto(*access_row) if access_row is not None else None
        )
        if access_family is not None:
            access_state = access_family.token_state
            if access_family.session.client_id != client_id:
                return TokenIntrospectionResponse(active=False)
            principal = await self._load_active_token_family_principal(access_family)
            if principal is None:
                return TokenIntrospectionResponse(active=False)
            try:
                token_payload = verify_access_token(
                    token=token,
                    issuer=self.settings.issuer,
                    access_token_audience=self.settings.access_token_audience,
                    key=key,
                )
            except OAuth2AccessTokenInvalidError:
                return TokenIntrospectionResponse(active=False)

            if access_state.access_expires_at <= now:
                return TokenIntrospectionResponse(active=False)
            if access_state.access_jti != token_payload.access_jti:
                return TokenIntrospectionResponse(active=False)
            if not self._access_token_matches_session(
                family=access_family,
                token_payload=token_payload,
                principal=principal,
            ):
                return TokenIntrospectionResponse(active=False)

            return TokenIntrospectionResponse(
                active=True,
                scope=token_payload.scope,
                client_id=str(token_payload.client_id),
                token_type="bearer",  # noqa: S106
                exp=int(access_state.access_expires_at.timestamp()),
                sub=token_payload.subject,
                aud=token_payload.audience,
                iss=self.settings.issuer,
                jti=token_payload.access_jti,
            )

        refresh_row = (
            await self.db_session.execute(
                select(OAuth2SessionDB, OAuth2TokenStateDB)
                .join(
                    OAuth2TokenStateDB,
                    OAuth2TokenStateDB.session_id == OAuth2SessionDB.id,
                )
                .where(OAuth2TokenStateDB.refresh_token_hash == token_hash)
            )
        ).one_or_none()
        refresh_family = (
            to_oauth2_token_family_dto(*refresh_row)
            if refresh_row is not None
            else None
        )
        if refresh_family is None or refresh_family.session.client_id != client_id:
            return TokenIntrospectionResponse(active=False)
        refresh_state = refresh_family.token_state
        if await self._load_active_token_family_principal(refresh_family) is None:
            return TokenIntrospectionResponse(active=False)
        if refresh_state.refresh_expires_at is None:
            return TokenIntrospectionResponse(active=False)
        if refresh_state.refresh_expires_at <= now:
            return TokenIntrospectionResponse(active=False)
        return TokenIntrospectionResponse(
            active=True,
            scope=refresh_family.session.scope,
            client_id=str(refresh_family.session.client_id),
            token_type="bearer",  # noqa: S106
            exp=int(refresh_state.refresh_expires_at.timestamp()),
        )

    async def _load_active_token_family_principal(
        self, family: OAuth2TokenFamilyReadDTO
    ) -> IdentityDTO | PrincipalType | None:
        """Resolve the live principal behind a stored token family."""
        session = family.session
        if not session.is_active():
            return None
        try:
            principal_type = session_principal_type(
                grant_type=session.grant_type,
                user_id=session.user_id,
                organization_id=session.organization_id,
            )
        except ValueError:
            return None
        client_row = await self.db_session.scalar(
            select(OAuth2ClientDB).where(OAuth2ClientDB.client_id == session.client_id)
        )
        client = (
            OAuth2ClientReadDTO.model_validate(client_row)
            if client_row is not None
            else None
        )
        if client is None or not client.is_active:
            return None
        if principal_type is PrincipalType.CLIENT:
            return principal_type

        return await load_eligible_oauth2_user_identity(
            db_session=self.db_session,
            user_id=session.user_id,
            organization_id=session.organization_id,
        )

    @staticmethod
    def _access_token_matches_session(
        *,
        family: OAuth2TokenFamilyReadDTO,
        token_payload: AccessTokenPayload,
        principal: IdentityDTO | PrincipalType,
    ) -> bool:
        """Return whether verified JWT claims match the persisted principal."""
        session = family.session
        if token_payload.client_id != session.client_id:
            return False
        if isinstance(principal, PrincipalType):
            return (
                principal is PrincipalType.CLIENT
                and token_payload.principal_type is PrincipalType.CLIENT
                and token_payload.subject == str(session.client_id)
                and token_payload.organization is None
            )
        return (
            token_payload.principal_type in {None, PrincipalType.USER}
            and token_payload.subject == str(principal.user.public_id)
            and token_payload.organization == str(principal.organization.public_id)
        )
