"""Email ownership changes for the user lifecycle."""

from dataclasses import dataclass
from datetime import datetime, UTC

from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models.user import UserDB
from app.errors import ObjectAlreadyExistsError
from app.identity.services.lifecycle_policy import EmailUpdatePolicy
from app.identity.users.commands import UserUpdateCommand
from app.identity.users.emails import (
    create_user_email,
    email_is_available,
    normalize_email,
    retire_email,
)
from app.identity.users.enums import UserEmailStatus


@dataclass(frozen=True, slots=True)
class PreparedUserUpdate:
    """Prepared user changes and their email lifecycle effects."""

    changes: dict[str, object]
    send_email_change: bool = False
    resend_invite: bool = False
    email_security_changed: bool = False


class UserEmailLifecycleService:
    """Preserve normalized email ownership during user mutations."""

    def __init__(self, db_session: AsyncSession) -> None:
        """Bind email lifecycle operations to the caller's transaction."""
        self.db_session = db_session

    async def require_available(
        self, *, email: str, current_user_id: int | None
    ) -> None:
        """Reject an email already used as a current or pending identity."""
        if not await email_is_available(
            self.db_session,
            email=email,
            excluding_user_id=current_user_id,
        ):
            raise ObjectAlreadyExistsError

    async def _retire(self, *, target: UserDB, status: UserEmailStatus) -> None:
        email = target.email_by_status(status)
        if email is not None:
            await retire_email(self.db_session, email=email)

    async def _create(
        self, *, target: UserDB, email: str, status: UserEmailStatus
    ) -> None:
        row = await create_user_email(
            self.db_session,
            user_id=target.id,
            email=email,
            status=status,
        )
        target.emails.append(row)

    async def prepare_update(
        self,
        *,
        target: UserDB,
        command: UserUpdateCommand,
        policy: EmailUpdatePolicy,
    ) -> PreparedUserUpdate:
        """Apply email state changes and return remaining user-column updates."""
        changes = command.changes()
        requested_email = changes.pop("email", None)
        requested_verified = changes.pop("email_verified", None)
        email_security_changed = False
        send_email_change = False
        resend_invite = False

        if requested_email is not None:
            normalized_email = normalize_email(str(requested_email))
            current = target.current_email
            pending = target.pending_email_record
            known_normalized = {current.normalized_email}
            if pending is not None:
                known_normalized.add(pending.normalized_email)
            if normalized_email not in known_normalized:
                await self.require_available(
                    email=normalized_email,
                    current_user_id=target.id,
                )
                direct_update = (
                    policy is EmailUpdatePolicy.DIRECT_IF_UNVERIFIED
                    and current.verified_at is None
                )
                if direct_update:
                    await self._retire(target=target, status=UserEmailStatus.CURRENT)
                    await self._retire(target=target, status=UserEmailStatus.PENDING)
                    await self._create(
                        target=target,
                        email=str(requested_email),
                        status=UserEmailStatus.CURRENT,
                    )
                    email_security_changed = True
                    resend_invite = True
                else:
                    await self._retire(target=target, status=UserEmailStatus.PENDING)
                    await self._create(
                        target=target,
                        email=str(requested_email),
                        status=UserEmailStatus.PENDING,
                    )
                    send_email_change = True

        if requested_verified is not None:
            current = target.current_email
            was_verified = current.verified_at is not None
            is_verified = bool(requested_verified)
            if was_verified != is_verified:
                current.verified_at = datetime.now(UTC) if is_verified else None
                email_security_changed = True
                await self.db_session.flush()

        return PreparedUserUpdate(
            changes=changes,
            send_email_change=send_email_change,
            resend_invite=resend_invite,
            email_security_changed=email_security_changed,
        )
