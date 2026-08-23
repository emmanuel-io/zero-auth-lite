"""Canonical-server auth token confirmation workflows."""

from datetime import datetime, UTC
from typing import cast, TYPE_CHECKING

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth_tokens.dtos import AuthTokenReadDTO
from app.auth_tokens.enums import AuthTokenPurpose
from app.auth_tokens.errors import InvalidAuthTokenError
from app.auth_tokens.service import AuthTokenService
from app.db.models.user import UserDB, UserEmailDB
from app.identity.users.emails import email_for_user, retire_email
from app.identity.users.enums import UserEmailStatus
from app.password.async_hashing import hash_password
from app.password.protocols import PasswordHasherProtocol
from app.security.session_revocation import SecuritySessionRevocationService


if TYPE_CHECKING:
    from sqlalchemy.engine import CursorResult
    from sqlalchemy.ext.asyncio import async_sessionmaker


class AuthTokenConfirmationService:
    """Apply consumed auth tokens to this application's identity workflows."""

    def __init__(
        self,
        *,
        auth_token_service: AuthTokenService,
        db_session: AsyncSession,
        security_revocation: SecuritySessionRevocationService,
        password_hasher: PasswordHasherProtocol,
        session_factory: "async_sessionmaker[AsyncSession]",
    ) -> None:
        """Initialize authentication-token confirmation workflows."""
        self.auth_token_service = auth_token_service
        self.db_session = db_session
        self.security_revocation = security_revocation
        self.password_hasher = password_hasher
        self.session_factory = session_factory

    async def _preview_password_token(
        self, *, token: str, purpose: AuthTokenPurpose
    ) -> None:
        """Reject invalid password tokens before starting expensive hashing."""
        async with self.session_factory() as preview_session:
            preview_service = AuthTokenService(
                db_session=preview_session,
                settings=self.auth_token_service.settings,
            )
            await preview_service.read_valid_token(
                token=token,
                purposes=frozenset({purpose}),
            )

    async def _finalize_security_change(self, *, user_id: int, reason: str) -> None:
        """Persist relational session revocation in the current transaction."""
        await self.security_revocation.revoke_user_security_sessions(
            user_id=user_id, reason=reason
        )

    async def _token_target(
        self, *, row: AuthTokenReadDTO, status: UserEmailStatus
    ) -> tuple[UserDB, UserEmailDB]:
        """Resolve the exact address version authorized by a consumed token."""
        target = (
            await self.db_session.execute(
                select(UserDB, UserEmailDB)
                .join(UserEmailDB, UserEmailDB.user_id == UserDB.id)
                .where(
                    UserEmailDB.id == row.user_email_id,
                    UserEmailDB.status == status,
                )
            )
        ).one_or_none()
        if target is None:
            raise InvalidAuthTokenError
        return target[0], target[1]

    async def confirm_verification(self, token: str) -> None:
        """Confirm a current or pending email address."""
        await self._confirm_email(
            token=token,
            purposes=frozenset(
                {AuthTokenPurpose.verify_email, AuthTokenPurpose.email_change}
            ),
        )

    async def confirm_registered_email(self, token: str) -> None:
        """Confirm the current email for a self-registered account."""
        await self._confirm_email(
            token=token,
            purposes=frozenset({AuthTokenPurpose.verify_email}),
        )

    async def confirm_email_change(self, token: str) -> None:
        """Confirm a pending replacement email address."""
        await self._confirm_email(
            token=token,
            purposes=frozenset({AuthTokenPurpose.email_change}),
        )

    async def _confirm_email(
        self,
        *,
        token: str,
        purposes: frozenset[AuthTokenPurpose],
    ) -> None:
        """Verify or promote the exact email row bound to a token."""
        row = await self.auth_token_service.consume_token(
            token=token,
            purposes=purposes,
        )
        if row.purpose == AuthTokenPurpose.email_change:
            user, pending = await self._token_target(
                row=row, status=UserEmailStatus.PENDING
            )
            current = await email_for_user(
                self.db_session,
                user_id=user.id,
                status=UserEmailStatus.CURRENT,
            )
            if current is None:
                raise InvalidAuthTokenError
            await retire_email(self.db_session, email=current)
            pending.status = UserEmailStatus.CURRENT
            pending.verified_at = datetime.now(UTC)
            pending.retired_at = None
            reason = "email_changed"
        else:
            user, current = await self._token_target(
                row=row, status=UserEmailStatus.CURRENT
            )
            current.verified_at = datetime.now(UTC)
            reason = "email_verified"
        await self.db_session.flush()
        await self._finalize_security_change(
            user_id=user.id,
            reason=reason,
        )

    async def reset_password(self, *, token: str, password: str) -> None:
        """Reset a password and verify the current email that received the token."""
        await self._preview_password_token(
            token=token,
            purpose=AuthTokenPurpose.reset_password,
        )
        password_hash = await hash_password(self.password_hasher, password)
        row = await self.auth_token_service.consume_token(
            token=token,
            purposes=frozenset({AuthTokenPurpose.reset_password}),
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
                .values(hashed_password=password_hash)
            ),
        )
        if not result.rowcount:
            raise InvalidAuthTokenError
        current.verified_at = datetime.now(UTC)
        await self.db_session.flush()
        await self._finalize_security_change(
            user_id=user.id,
            reason="password_reset",
        )

    async def accept_invite(self, *, token: str, password: str) -> None:
        """Accept an application invite by setting the first password."""
        await self._preview_password_token(token=token, purpose=AuthTokenPurpose.invite)
        password_hash = await hash_password(self.password_hasher, password)
        row = await self.auth_token_service.consume_token(
            token=token,
            purposes=frozenset({AuthTokenPurpose.invite}),
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
                .values(hashed_password=password_hash)
            ),
        )
        if not result.rowcount:
            raise InvalidAuthTokenError
        current.verified_at = datetime.now(UTC)
        await self.db_session.flush()
        await self._finalize_security_change(
            user_id=user.id,
            reason="invite_accepted",
        )
