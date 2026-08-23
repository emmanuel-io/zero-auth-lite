"""Resolve anonymous authentication requests to immutable event targets."""

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models.user import UserDB, UserEmailDB
from app.events.protocols import EventPublisher
from app.events.types import AccountVerificationRequested, PasswordResetRequested
from app.identity.users.emails import normalize_email
from app.identity.users.enums import UserEmailStatus
from app.identity.users.types import UserEmail
from app.public_ids import PublicId


class AuthNotificationRequestService:
    """Publish opaque authentication requests bound to the current user."""

    def __init__(
        self, *, db_session: AsyncSession, event_publisher: EventPublisher
    ) -> None:
        """Initialize the request resolver in the caller's transaction."""
        self.db_session = db_session
        self.event_publisher = event_publisher

    async def _user_by_email(
        self, email: UserEmail
    ) -> tuple[UserDB, UserEmailDB] | None:
        """Return the account currently owning a normalized email address."""
        row = (
            await self.db_session.execute(
                select(UserDB, UserEmailDB)
                .join(UserEmailDB, UserEmailDB.user_id == UserDB.id)
                .where(
                    UserEmailDB.normalized_email == normalize_email(str(email)),
                    UserEmailDB.status == UserEmailStatus.CURRENT,
                )
            )
        ).one_or_none()
        return (row[0], row[1]) if row is not None else None

    async def request_password_reset(self, email: UserEmail) -> None:
        """Publish a reset request when an active account currently exists."""
        target = await self._user_by_email(email)
        if target is None or not target[0].is_active:
            return
        user, user_email = target
        await self.event_publisher.publish(
            PasswordResetRequested(
                user_public_id=PublicId(user.public_id),
                user_email_id=user_email.id,
            )
        )

    async def request_account_verification(self, email: UserEmail) -> None:
        """Publish a verification request for an active unverified account."""
        target = await self._user_by_email(email)
        if target is None:
            return
        user, user_email = target
        if not user.is_active or user_email.verified_at is not None:
            return
        await self.event_publisher.publish(
            AccountVerificationRequested(
                user_public_id=PublicId(user.public_id),
                user_email_id=user_email.id,
            )
        )
