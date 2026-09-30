"""Shared OAuth2 token creation and new-session persistence."""

from datetime import datetime

from cryptography.hazmat.primitives.asymmetric import ed25519
from sqlalchemy import insert
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models.oauth2_session import OAuth2SessionDB
from app.db.models.oauth2_token_state import OAuth2TokenStateDB
from app.oauth2.schemas import OAuth2TokenResponse
from app.oauth2.settings import OAuth2Settings
from app.oauth2.tokens.access import (
    AccessTokenPayload,
    create_issued_tokens,
    IssuedTokens,
)
from app.oauth2.tokens.dtos import IssuedTokenSessionDTO, NewTokenSessionDTO
from app.oauth2.tokens.hash import hash_oauth2_token


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
    ) -> IssuedTokens:
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
    ) -> IssuedTokens:
        """Create token material using the canonical OAuth2 settings."""
        return create_issued_tokens(
            access_payload=access_payload,
            access_token_lifetime_seconds=self.settings.access_token_lifetime_seconds,
            refresh_token_lifetime_seconds=(
                self.settings.refresh_token_lifetime_seconds
            ),
            issuer=self.settings.issuer,
            key=self.signing_key,
            key_id=self.settings.signing_key_id,
            include_refresh_token=include_refresh_token,
            refresh_deadline=refresh_deadline,
        )

    async def issue_new_session(
        self, data: NewTokenSessionDTO
    ) -> IssuedTokenSessionDTO:
        """Create tokens and persist their new authorization session atomically."""
        tokens = self._create_tokens(
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
            OAuth2TokenStateDB(
                access_token_hash=hash_oauth2_token(
                    token=tokens.access_token, secret=secret
                ),
                refresh_token_hash=(
                    hash_oauth2_token(token=tokens.refresh_token, secret=secret)
                    if tokens.refresh_token is not None
                    else None
                ),
                access_expires_at=tokens.access_expires_at,
                refresh_expires_at=tokens.refresh_expires_at,
                access_jti=tokens.access_jti,
                session_id=oauth2_session.id,
            )
        )
        await self.db_session.flush()
        return IssuedTokenSessionDTO(
            tokens=tokens,
            session_id=oauth2_session.id,
            session_public_id=oauth2_session.public_id,
        )

    def build_response(
        self, tokens: IssuedTokens, *, id_token: str | None = None
    ) -> OAuth2TokenResponse:
        """Build the standardized token response from issued token material."""
        return OAuth2TokenResponse(
            access_token=tokens.access_token,
            refresh_token=tokens.refresh_token,
            id_token=id_token,
            expires_in=tokens.access_token_lifetime_seconds,
            token_type="bearer",  # noqa: S106
        )
