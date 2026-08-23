"""Shared OAuth2 token creation and new-session persistence."""

from datetime import datetime

from cryptography.hazmat.primitives.asymmetric import ed25519
from sqlalchemy import insert
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models.oauth2_session import OAuth2SessionDB
from app.db.models.oauth2_token_pair import OAuth2TokenPairDB
from app.oauth2.schemas import TokenPair
from app.oauth2.settings import OAuth2Settings
from app.oauth2.tokens.access import (
    AccessTokenPayload,
    create_token_pair_data,
    TokenPairData,
)
from app.oauth2.tokens.dtos import IssuedTokenSessionDTO, NewTokenSessionDTO
from app.oauth2.tokens.hash import hash_oauth2_token
from app.public_ids import PublicId


class TokenIssuanceService:
    """Create token material and persist new OAuth2 token sessions."""

    def __init__(
        self,
        *,
        db_session: AsyncSession,
        settings: OAuth2Settings,
        signing_key: ed25519.Ed25519PrivateKey | str,
    ) -> None:
        """Initialize issuance with transaction and signing dependencies."""
        self.db_session = db_session
        self.settings = settings
        self.signing_key = signing_key

    def create_rotation_tokens(
        self,
        *,
        access_payload: AccessTokenPayload,
        refresh_deadline: datetime,
    ) -> TokenPairData:
        """Create replacement tokens without changing persisted family state."""
        return self._create_tokens(
            access_payload=access_payload,
            include_refresh_token=True,
            refresh_deadline=refresh_deadline,
        )

    def _create_tokens(
        self,
        *,
        access_payload: AccessTokenPayload,
        include_refresh_token: bool,
        refresh_deadline: datetime | None = None,
    ) -> TokenPairData:
        """Create token material using the canonical OAuth2 settings."""
        return create_token_pair_data(
            access_payload=access_payload,
            access_token_lifetime_seconds=self.settings.access_token_lifetime_seconds,
            refresh_token_lifetime_seconds=(
                self.settings.refresh_token_lifetime_seconds
            ),
            jwt_issuer=self.settings.jwt_issuer,
            key=self.signing_key,
            key_id=self.settings.jwt_key_id,
            include_refresh_token=include_refresh_token,
            refresh_deadline=refresh_deadline,
        )

    async def issue_new_session(
        self, data: NewTokenSessionDTO
    ) -> IssuedTokenSessionDTO:
        """Create tokens and persist their new authorization session atomically."""
        token_pair = self._create_tokens(
            access_payload=data.access_payload,
            include_refresh_token=data.include_refresh_token,
        )
        oauth2_session = (
            await self.db_session.execute(
                insert(OAuth2SessionDB)
                .values(
                    client_id=data.client_id,
                    grant_type=data.grant_type,
                    scope=data.scope,
                    user_id=data.user_id,
                    organization_id=data.organization_id,
                )
                .returning(OAuth2SessionDB)
            )
        ).scalar_one()
        secret = self.settings.token_hash_secret.get_secret_value()
        self.db_session.add(
            OAuth2TokenPairDB(
                access_token_hash=hash_oauth2_token(
                    token=token_pair.access_token, secret=secret
                ),
                refresh_token_hash=(
                    hash_oauth2_token(token=token_pair.refresh_token, secret=secret)
                    if token_pair.refresh_token is not None
                    else None
                ),
                access_expires_at=token_pair.access_expires_at,
                refresh_expires_at=token_pair.refresh_expires_at,
                access_jti=token_pair.access_jti,
                session_id=oauth2_session.id,
            )
        )
        await self.db_session.flush()
        return IssuedTokenSessionDTO(
            token_pair=token_pair,
            session_id=oauth2_session.id,
            session_public_id=PublicId(oauth2_session.public_id),
        )

    def build_response(
        self, token_pair: TokenPairData, *, id_token: str | None = None
    ) -> TokenPair:
        """Build the standardized token response from issued token material."""
        return TokenPair(
            access_token=token_pair.access_token,
            refresh_token=token_pair.refresh_token,
            id_token=id_token,
            expires_in=self.settings.access_token_lifetime_seconds,
            token_type="bearer",  # noqa: S106
        )
