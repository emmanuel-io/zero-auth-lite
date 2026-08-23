"""Reusable single-use authentication-token lifecycle."""

import base64
import hashlib
import hmac
import secrets
from dataclasses import asdict
from datetime import datetime, timedelta, UTC

from sqlalchemy import and_, insert, or_, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth_tokens.dtos import AuthTokenCreateDTO, AuthTokenReadDTO
from app.auth_tokens.enums import AuthTokenPurpose
from app.auth_tokens.errors import (
    AuthTokenDerivationKeyError,
    InvalidAuthTokenError,
)
from app.auth_tokens.settings import AuthTokenSettings
from app.auth_tokens.specs import AuthTokenSpecs
from app.core.time import as_utc_aware
from app.db.models.auth_token import UserAuthTokenDB


class AuthTokenService:
    """Issue and consume single-use auth workflow tokens."""

    def __init__(
        self,
        *,
        db_session: AsyncSession,
        settings: AuthTokenSettings,
    ) -> None:
        """Initialize the service with the application database and settings."""
        self.db_session = db_session
        self.settings = settings

    @staticmethod
    def _to_dto(row: UserAuthTokenDB) -> AuthTokenReadDTO:
        """Return the stable auth-token data shape for an ORM row."""
        return AuthTokenReadDTO(
            id=row.id,
            user_email_id=row.user_email_id,
            purpose=AuthTokenPurpose(row.purpose),
            token_hash=row.token_hash,
            expires_at=as_utc_aware(row.expires_at),
            source_event_id=row.source_event_id,
            source_event_occurred_at=(
                as_utc_aware(row.source_event_occurred_at)
                if row.source_event_occurred_at is not None
                else None
            ),
            derivation_key_id=row.derivation_key_id,
            used_at=as_utc_aware(row.used_at) if row.used_at is not None else None,
        )

    async def _replace_active(self, data: AuthTokenCreateDTO) -> AuthTokenReadDTO:
        """Invalidate the active token for a purpose and insert its replacement."""
        await self.db_session.execute(
            update(UserAuthTokenDB)
            .where(UserAuthTokenDB.user_email_id == data.user_email_id)
            .where(UserAuthTokenDB.purpose == data.purpose)
            .where(UserAuthTokenDB.used_at.is_(None))
            .values(used_at=datetime.now(data.expires_at.tzinfo))
        )
        row = (
            await self.db_session.execute(
                insert(UserAuthTokenDB)
                .values(**asdict(data))
                .returning(UserAuthTokenDB)
            )
        ).scalar_one()
        await self.db_session.flush()
        return self._to_dto(row)

    def _token_hash(self, token: str) -> str:
        """Return the stored digest for a raw auth workflow token."""
        return hashlib.sha256(token.encode()).hexdigest()

    def _token_for_event(
        self,
        *,
        event_id: str,
        user_email_id: int,
        purpose: AuthTokenPurpose,
        derivation_key_id: str,
    ) -> str:
        """Derive a stable high-entropy token for one notification event."""
        secret = self.settings.derivation_secret_for(derivation_key_id)
        if secret is None:
            msg = (
                "Auth-token derivation key "
                f"{derivation_key_id!r} is unavailable; retain it until all tokens "
                "using it have expired or been consumed."
            )
            raise AuthTokenDerivationKeyError(msg)
        message = f"{event_id}:{user_email_id}:{purpose.value}".encode()
        digest = hmac.new(
            secret.get_secret_value().encode(),
            message,
            hashlib.sha256,
        ).digest()
        return base64.urlsafe_b64encode(digest).rstrip(b"=").decode()

    def _ttl_for_purpose(self, purpose: AuthTokenPurpose) -> int:
        """Return the configured token lifetime for a purpose."""
        if purpose in {
            AuthTokenPurpose.verify_email,
            AuthTokenPurpose.email_change,
        }:
            return self.settings.verify_token_ttl_seconds
        if purpose == AuthTokenPurpose.invite:
            return self.settings.invite_token_ttl_seconds
        return self.settings.reset_token_ttl_seconds

    async def issue_token(
        self, *, user_email_id: int, purpose: AuthTokenPurpose
    ) -> str:
        """Create a raw token and store only its digest.

        Args:
            user_email_id: Address that may later consume the token.
            purpose: Workflow purpose for the token.

        Returns:
            str: Raw token for application-owned delivery.
        """
        token = secrets.token_urlsafe(AuthTokenSpecs.RANDOM_TOKEN_BYTES)
        await self._replace_active(
            AuthTokenCreateDTO(
                user_email_id=user_email_id,
                purpose=purpose,
                token_hash=self._token_hash(token),
                expires_at=datetime.now(UTC)
                + timedelta(seconds=self._ttl_for_purpose(purpose)),
            )
        )
        return token

    async def issue_token_for_event(
        self,
        *,
        event_id: str,
        event_occurred_at: datetime,
        user_email_id: int,
        purpose: AuthTokenPurpose,
    ) -> str | None:
        """Return an idempotent token, renewing it after delivery outages."""
        existing_row = await self.db_session.scalar(
            select(UserAuthTokenDB).where(UserAuthTokenDB.source_event_id == event_id)
        )
        existing = self._to_dto(existing_row) if existing_row is not None else None
        if existing is not None:
            if existing.user_email_id != user_email_id or existing.purpose != purpose:
                raise InvalidAuthTokenError
            if existing.used_at is not None:
                return None
            if existing.derivation_key_id is None:
                msg = f"Event token {event_id!r} has no derivation key identifier."
                raise AuthTokenDerivationKeyError(msg)
            token = self._token_for_event(
                event_id=event_id,
                user_email_id=user_email_id,
                purpose=purpose,
                derivation_key_id=existing.derivation_key_id,
            )
            if not hmac.compare_digest(self._token_hash(token), existing.token_hash):
                msg = (
                    "Configured auth-token derivation secret does not match "
                    f"persisted key {existing.derivation_key_id!r}."
                )
                raise AuthTokenDerivationKeyError(msg)
            if existing.expires_at <= datetime.now(UTC):
                renewed_row = await self.db_session.scalar(
                    update(UserAuthTokenDB)
                    .where(UserAuthTokenDB.source_event_id == event_id)
                    .where(UserAuthTokenDB.used_at.is_(None))
                    .values(
                        expires_at=datetime.now(UTC)
                        + timedelta(seconds=self._ttl_for_purpose(purpose))
                    )
                    .returning(UserAuthTokenDB)
                )
                await self.db_session.flush()
                if renewed_row is None:
                    return None
            return token
        derivation_key_id = self.settings.derivation_key_id
        token = self._token_for_event(
            event_id=event_id,
            user_email_id=user_email_id,
            purpose=purpose,
            derivation_key_id=derivation_key_id,
        )
        data = AuthTokenCreateDTO(
            user_email_id=user_email_id,
            purpose=purpose,
            token_hash=self._token_hash(token),
            expires_at=datetime.now(UTC)
            + timedelta(seconds=self._ttl_for_purpose(purpose)),
            source_event_id=event_id,
            source_event_occurred_at=event_occurred_at,
            derivation_key_id=derivation_key_id,
        )
        newer_exists = await self.db_session.scalar(
            select(UserAuthTokenDB.id)
            .where(UserAuthTokenDB.user_email_id == data.user_email_id)
            .where(UserAuthTokenDB.purpose == data.purpose)
            .where(UserAuthTokenDB.source_event_occurred_at.is_not(None))
            .where(
                or_(
                    UserAuthTokenDB.source_event_occurred_at
                    > data.source_event_occurred_at,
                    and_(
                        UserAuthTokenDB.source_event_occurred_at
                        == data.source_event_occurred_at,
                        UserAuthTokenDB.source_event_id > data.source_event_id,
                    ),
                )
            )
            .limit(1)
        )
        if newer_exists is not None:
            return None
        await self._replace_active(data)
        return token

    async def consume_token(
        self,
        *,
        token: str,
        purposes: frozenset[AuthTokenPurpose],
    ) -> AuthTokenReadDTO:
        """Consume a valid token once and return its stored metadata.

        Args:
            token: Raw token received from an application-owned delivery channel.
            purposes: Accepted token purposes for this confirmation action.

        Returns:
            AuthTokenReadDTO: Consumed token metadata.

        Raises:
            InvalidAuthTokenError: If the token is missing, used, expired,
                or for a different purpose.
        """
        now = datetime.now(UTC)
        row = await self.db_session.scalar(
            update(UserAuthTokenDB)
            .where(UserAuthTokenDB.token_hash == self._token_hash(token))
            .where(UserAuthTokenDB.purpose.in_(purposes))
            .where(UserAuthTokenDB.used_at.is_(None))
            .where(UserAuthTokenDB.expires_at > now)
            .values(used_at=now)
            .returning(UserAuthTokenDB)
        )
        await self.db_session.flush()
        if row is None:
            raise InvalidAuthTokenError
        return self._to_dto(row)

    async def read_valid_token(
        self,
        *,
        token: str,
        purposes: frozenset[AuthTokenPurpose],
    ) -> AuthTokenReadDTO:
        """Read valid token metadata without consuming the single-use token."""
        row = await self.db_session.scalar(
            select(UserAuthTokenDB)
            .where(UserAuthTokenDB.token_hash == self._token_hash(token))
            .where(UserAuthTokenDB.purpose.in_(purposes))
            .where(UserAuthTokenDB.used_at.is_(None))
            .where(UserAuthTokenDB.expires_at > datetime.now(UTC))
        )
        if row is None:
            raise InvalidAuthTokenError
        return self._to_dto(row)
