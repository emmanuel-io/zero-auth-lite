"""Reusable single-use workflow-token lifecycle."""

import base64
import hashlib
import hmac
from dataclasses import asdict
from datetime import datetime, timedelta, UTC

from sqlalchemy import and_, insert, or_, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.time import as_utc_aware
from app.db.models.user import UserEmailDB
from app.db.models.workflow_token import UserWorkflowTokenDB
from app.workflow_tokens.dtos import WorkflowTokenCreateDTO, WorkflowTokenReadDTO
from app.workflow_tokens.enums import WorkflowTokenPurpose
from app.workflow_tokens.errors import (
    InvalidWorkflowTokenError,
    WorkflowTokenDerivationKeyError,
)
from app.workflow_tokens.settings import WorkflowTokenSettings


CREDENTIAL_TOKEN_PURPOSES = frozenset(
    {WorkflowTokenPurpose.INVITE, WorkflowTokenPurpose.RESET_PASSWORD}
)


async def invalidate_active_credential_tokens(
    db_session: AsyncSession, *, user_id: int
) -> None:
    """Invalidate every unused token capable of replacing a user's password."""
    await db_session.execute(
        update(UserWorkflowTokenDB)
        .where(
            UserWorkflowTokenDB.user_email_id.in_(
                select(UserEmailDB.id).where(UserEmailDB.user_id == user_id)
            )
        )
        .where(UserWorkflowTokenDB.purpose.in_(CREDENTIAL_TOKEN_PURPOSES))
        .where(UserWorkflowTokenDB.used_at.is_(None))
        .values(used_at=datetime.now(UTC))
    )


async def invalidate_all_active_workflow_tokens(
    db_session: AsyncSession, *, user_id: int
) -> None:
    """Invalidate every unused identity-workflow token for one user."""
    await db_session.execute(
        update(UserWorkflowTokenDB)
        .where(
            UserWorkflowTokenDB.user_email_id.in_(
                select(UserEmailDB.id).where(UserEmailDB.user_id == user_id)
            )
        )
        .where(UserWorkflowTokenDB.used_at.is_(None))
        .values(used_at=datetime.now(UTC))
    )


class WorkflowTokenService:
    """Issue and consume single-use identity workflow tokens."""

    def __init__(
        self,
        *,
        db_session: AsyncSession,
        settings: WorkflowTokenSettings,
    ) -> None:
        """Initialize the service with the application database and settings."""
        self.db_session = db_session
        self.settings = settings

    @staticmethod
    def _to_dto(row: UserWorkflowTokenDB) -> WorkflowTokenReadDTO:
        """Return the stable workflow-token data shape for an ORM row."""
        return WorkflowTokenReadDTO(
            id=row.id,
            user_email_id=row.user_email_id,
            purpose=WorkflowTokenPurpose(row.purpose),
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

    async def _replace_active(
        self, data: WorkflowTokenCreateDTO
    ) -> WorkflowTokenReadDTO:
        """Invalidate the active token for a purpose and insert its replacement."""
        await self.db_session.execute(
            update(UserWorkflowTokenDB)
            .where(UserWorkflowTokenDB.user_email_id == data.user_email_id)
            .where(UserWorkflowTokenDB.purpose == data.purpose)
            .where(UserWorkflowTokenDB.used_at.is_(None))
            .values(used_at=datetime.now(data.expires_at.tzinfo))
        )
        row = (
            await self.db_session.execute(
                insert(UserWorkflowTokenDB)
                .values(**asdict(data))
                .returning(UserWorkflowTokenDB)
            )
        ).scalar_one()
        await self.db_session.flush()
        return self._to_dto(row)

    def _token_hash(self, token: str) -> str:
        """Return the stored digest for a raw identity workflow token."""
        return hashlib.sha256(token.encode()).hexdigest()

    def _token_for_event(
        self,
        *,
        event_id: str,
        user_email_id: int,
        purpose: WorkflowTokenPurpose,
        derivation_key_id: str,
    ) -> str:
        """Derive a stable high-entropy token for one notification event."""
        secret = self.settings.derivation_secret_for(derivation_key_id)
        if secret is None:
            msg = (
                "Workflow-token derivation key "
                f"{derivation_key_id!r} is unavailable; retain it until all tokens "
                "using it have expired or been consumed."
            )
            raise WorkflowTokenDerivationKeyError(msg)
        message = f"{event_id}:{user_email_id}:{purpose.value}".encode()
        digest = hmac.new(
            secret.get_secret_value().encode(),
            message,
            hashlib.sha256,
        ).digest()
        return base64.urlsafe_b64encode(digest).rstrip(b"=").decode()

    def _ttl_for_purpose(self, purpose: WorkflowTokenPurpose) -> int:
        """Return the configured token lifetime for a purpose."""
        if purpose in {
            WorkflowTokenPurpose.VERIFY_EMAIL,
            WorkflowTokenPurpose.EMAIL_CHANGE,
        }:
            return self.settings.verify_token_ttl_seconds
        if purpose == WorkflowTokenPurpose.INVITE:
            return self.settings.invite_token_ttl_seconds
        return self.settings.reset_token_ttl_seconds

    async def issue_token_for_event(
        self,
        *,
        event_id: str,
        event_occurred_at: datetime,
        user_email_id: int,
        purpose: WorkflowTokenPurpose,
    ) -> str | None:
        """Return an idempotent token, renewing it after delivery outages."""
        existing_row = await self.db_session.scalar(
            select(UserWorkflowTokenDB).where(
                UserWorkflowTokenDB.source_event_id == event_id
            )
        )
        existing = self._to_dto(existing_row) if existing_row is not None else None
        if existing is not None:
            if existing.user_email_id != user_email_id or existing.purpose != purpose:
                raise InvalidWorkflowTokenError
            if existing.used_at is not None:
                return None
            if existing.derivation_key_id is None:
                msg = f"Event token {event_id!r} has no derivation key identifier."
                raise WorkflowTokenDerivationKeyError(msg)
            token = self._token_for_event(
                event_id=event_id,
                user_email_id=user_email_id,
                purpose=purpose,
                derivation_key_id=existing.derivation_key_id,
            )
            if not hmac.compare_digest(self._token_hash(token), existing.token_hash):
                msg = (
                    "Configured workflow-token derivation secret does not match "
                    f"persisted key {existing.derivation_key_id!r}."
                )
                raise WorkflowTokenDerivationKeyError(msg)
            if existing.expires_at <= datetime.now(UTC):
                renewed_row = await self.db_session.scalar(
                    update(UserWorkflowTokenDB)
                    .where(UserWorkflowTokenDB.source_event_id == event_id)
                    .where(UserWorkflowTokenDB.used_at.is_(None))
                    .values(
                        expires_at=datetime.now(UTC)
                        + timedelta(seconds=self._ttl_for_purpose(purpose))
                    )
                    .returning(UserWorkflowTokenDB)
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
        data = WorkflowTokenCreateDTO(
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
            select(UserWorkflowTokenDB.id)
            .where(UserWorkflowTokenDB.user_email_id == data.user_email_id)
            .where(UserWorkflowTokenDB.purpose == data.purpose)
            .where(UserWorkflowTokenDB.source_event_occurred_at.is_not(None))
            .where(
                or_(
                    UserWorkflowTokenDB.source_event_occurred_at
                    > data.source_event_occurred_at,
                    and_(
                        UserWorkflowTokenDB.source_event_occurred_at
                        == data.source_event_occurred_at,
                        UserWorkflowTokenDB.source_event_id > data.source_event_id,
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
        purposes: frozenset[WorkflowTokenPurpose],
    ) -> WorkflowTokenReadDTO:
        """Consume a valid token once and return its stored metadata.

        Raises:
            InvalidWorkflowTokenError: If the token is missing, used, expired,
                or for a different purpose.
        """
        now = datetime.now(UTC)
        row = await self.db_session.scalar(
            update(UserWorkflowTokenDB)
            .where(UserWorkflowTokenDB.token_hash == self._token_hash(token))
            .where(UserWorkflowTokenDB.purpose.in_(purposes))
            .where(UserWorkflowTokenDB.used_at.is_(None))
            .where(UserWorkflowTokenDB.expires_at > now)
            .values(used_at=now)
            .returning(UserWorkflowTokenDB)
        )
        await self.db_session.flush()
        if row is None:
            raise InvalidWorkflowTokenError
        return self._to_dto(row)

    async def read_valid_token(
        self,
        *,
        token: str,
        purposes: frozenset[WorkflowTokenPurpose],
    ) -> WorkflowTokenReadDTO:
        """Read valid token metadata without consuming the single-use token."""
        row = await self.db_session.scalar(
            select(UserWorkflowTokenDB)
            .where(UserWorkflowTokenDB.token_hash == self._token_hash(token))
            .where(UserWorkflowTokenDB.purpose.in_(purposes))
            .where(UserWorkflowTokenDB.used_at.is_(None))
            .where(UserWorkflowTokenDB.expires_at > datetime.now(UTC))
        )
        if row is None:
            raise InvalidWorkflowTokenError
        return self._to_dto(row)
