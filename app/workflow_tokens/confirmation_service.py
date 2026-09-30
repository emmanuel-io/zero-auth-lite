"""Canonical-server workflow token confirmation workflows."""

from datetime import datetime, UTC
from typing import cast, TYPE_CHECKING

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.browser_sessions.enums import BrowserSessionRevocationReason
from app.db.models.user import UserDB, UserEmailDB
from app.identity.users.emails import email_for_user, retire_email
from app.identity.users.enums import UserEmailStatus
from app.password.async_hashing import hash_password
from app.password.protocols import PasswordHasherProtocol
from app.security.session_revocation import SecuritySessionRevocationService
from app.workflow_tokens.dtos import WorkflowTokenReadDTO
from app.workflow_tokens.enums import WorkflowTokenPurpose
from app.workflow_tokens.errors import InvalidWorkflowTokenError
from app.workflow_tokens.service import (
    invalidate_active_credential_tokens,
    WorkflowTokenService,
)


if TYPE_CHECKING:
    from sqlalchemy.engine import CursorResult
    from sqlalchemy.ext.asyncio import async_sessionmaker


class WorkflowTokenConfirmationService:
    """Apply consumed workflow tokens to this application's identity workflows."""

    def __init__(
        self,
        *,
        workflow_token_service: WorkflowTokenService,
        db_session: AsyncSession,
        security_revocation: SecuritySessionRevocationService,
        password_hasher: PasswordHasherProtocol,
        session_factory: "async_sessionmaker[AsyncSession]",
    ) -> None:
        """Initialize workflow-token confirmation workflows."""
        self.workflow_token_service = workflow_token_service
        self.db_session = db_session
        self.security_revocation = security_revocation
        self.password_hasher = password_hasher
        self.session_factory = session_factory

    async def _preview_password_token(
        self, *, token: str, purpose: WorkflowTokenPurpose
    ) -> None:
        """Reject invalid password tokens before starting expensive hashing."""
        async with self.session_factory() as preview_session:
            preview_service = WorkflowTokenService(
                db_session=preview_session,
                settings=self.workflow_token_service.settings,
            )
            await preview_service.read_valid_token(
                token=token,
                purposes=frozenset({purpose}),
            )

    async def _finalize_security_change(
        self, *, user_id: int, browser_reason: BrowserSessionRevocationReason
    ) -> None:
        """Persist relational session revocation in the current transaction."""
        await self.security_revocation.revoke_user_security_sessions(
            user_id=user_id, browser_reason=browser_reason
        )

    async def _token_target(
        self, *, row: WorkflowTokenReadDTO, status: UserEmailStatus
    ) -> tuple[UserDB, UserEmailDB]:
        """Resolve the exact address version authorized by a consumed token."""
        target = (
            await self.db_session.execute(
                select(UserDB, UserEmailDB)
                .join(UserEmailDB, UserEmailDB.user_id == UserDB.id)
                .where(
                    UserEmailDB.id == row.user_email_id,
                    UserEmailDB.status == status,
                    UserDB.is_active.is_(True),
                )
            )
        ).one_or_none()
        if target is None:
            raise InvalidWorkflowTokenError
        return target[0], target[1]

    async def confirm_verification(self, token: str) -> None:
        """Confirm a current or pending email address."""
        await self._confirm_email(
            token=token,
            purposes=frozenset(
                {WorkflowTokenPurpose.VERIFY_EMAIL, WorkflowTokenPurpose.EMAIL_CHANGE}
            ),
        )

    async def confirm_registered_email(self, token: str) -> None:
        """Confirm the current email for a self-registered account."""
        await self._confirm_email(
            token=token,
            purposes=frozenset({WorkflowTokenPurpose.VERIFY_EMAIL}),
        )

    async def confirm_email_change(self, token: str) -> None:
        """Confirm a pending replacement email address."""
        await self._confirm_email(
            token=token,
            purposes=frozenset({WorkflowTokenPurpose.EMAIL_CHANGE}),
        )

    async def _confirm_email(
        self,
        *,
        token: str,
        purposes: frozenset[WorkflowTokenPurpose],
    ) -> None:
        """Verify or promote the exact email row bound to a token."""
        row = await self.workflow_token_service.consume_token(
            token=token,
            purposes=purposes,
        )
        if row.purpose == WorkflowTokenPurpose.EMAIL_CHANGE:
            user, pending = await self._token_target(
                row=row, status=UserEmailStatus.PENDING
            )
            current = await email_for_user(
                self.db_session,
                user_id=user.id,
                status=UserEmailStatus.CURRENT,
            )
            if current is None:
                raise InvalidWorkflowTokenError
            await retire_email(self.db_session, email=current)
            pending.status = UserEmailStatus.CURRENT
            pending.verified_at = datetime.now(UTC)
            pending.retired_at = None
            browser_reason = BrowserSessionRevocationReason.EMAIL_CHANGED
        else:
            user, current = await self._token_target(
                row=row, status=UserEmailStatus.CURRENT
            )
            current.verified_at = datetime.now(UTC)
            browser_reason = BrowserSessionRevocationReason.EMAIL_VERIFIED
        await self.db_session.flush()
        await self._finalize_security_change(
            user_id=user.id,
            browser_reason=browser_reason,
        )

    async def reset_password(self, *, token: str, password: str) -> None:
        """Reset a password and verify the current email that received the token."""
        await self._preview_password_token(
            token=token,
            purpose=WorkflowTokenPurpose.RESET_PASSWORD,
        )
        password_hash = await hash_password(self.password_hasher, password)
        row = await self.workflow_token_service.consume_token(
            token=token,
            purposes=frozenset({WorkflowTokenPurpose.RESET_PASSWORD}),
        )
        user, current = await self._token_target(
            row=row, status=UserEmailStatus.CURRENT
        )
        result = cast(
            "CursorResult[object]",
            await self.db_session.execute(
                update(UserDB)
                .where(UserDB.id == user.id)
                .where(UserDB.is_active.is_(True))
                .values(hashed_password=password_hash, invitation_pending=False)
            ),
        )
        if not result.rowcount:
            raise InvalidWorkflowTokenError
        await invalidate_active_credential_tokens(
            self.db_session,
            user_id=user.id,
        )
        current.verified_at = datetime.now(UTC)
        await self.db_session.flush()
        await self._finalize_security_change(
            user_id=user.id,
            browser_reason=BrowserSessionRevocationReason.PASSWORD_RESET,
        )

    async def accept_invite(self, *, token: str, password: str) -> None:
        """Accept an application invite by setting the first password."""
        await self._preview_password_token(
            token=token, purpose=WorkflowTokenPurpose.INVITE
        )
        password_hash = await hash_password(self.password_hasher, password)
        row = await self.workflow_token_service.consume_token(
            token=token,
            purposes=frozenset({WorkflowTokenPurpose.INVITE}),
        )
        user, current = await self._token_target(
            row=row, status=UserEmailStatus.CURRENT
        )
        result = cast(
            "CursorResult[object]",
            await self.db_session.execute(
                update(UserDB)
                .where(UserDB.id == user.id)
                .where(UserDB.is_active.is_(True))
                .where(UserDB.invitation_pending.is_(True))
                .values(hashed_password=password_hash, invitation_pending=False)
            ),
        )
        if not result.rowcount:
            raise InvalidWorkflowTokenError
        await invalidate_active_credential_tokens(
            self.db_session,
            user_id=user.id,
        )
        current.verified_at = datetime.now(UTC)
        await self.db_session.flush()
        await self._finalize_security_change(
            user_id=user.id,
            browser_reason=BrowserSessionRevocationReason.INVITE_ACCEPTED,
        )
