"""Build canonical-server authentication notification emails."""

from collections.abc import Awaitable, Callable
from datetime import datetime
from typing import cast
from urllib.parse import urlencode
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models.organization import OrganizationDB
from app.db.models.organization_membership import OrganizationMembershipDB
from app.db.models.user import UserDB, UserEmailDB
from app.identity.dtos import IdentityDTO, IdentityUserDTO
from app.identity.mapping import to_identity
from app.identity.users.emails import active_email_loader
from app.identity.users.enums import UserEmailStatus
from app.mail.schemas import EmailAddress, TemplateEmail
from app.notifications.event import NotificationEvent
from app.notifications.events import (
    AccountVerificationRequested,
    EmailChangeRequested,
    InviteCreated,
    NOTIFICATION_EVENT_CLASSES,
    PasswordResetRequested,
)
from app.settings.ui import UIURLs
from app.workflow_tokens.enums import WorkflowTokenPurpose
from app.workflow_tokens.service import WorkflowTokenService


type NotificationBuilder = Callable[
    [NotificationEvent], Awaitable[TemplateEmail | None]
]


class UnsupportedNotificationEventError(Exception):
    """Raised when a registered notification event has no message builder."""


class AuthNotificationBuilder:
    """Prepare retry-safe notification messages without sending them."""

    def __init__(
        self,
        *,
        db_session: AsyncSession,
        workflow_token_service: WorkflowTokenService,
        workflow_urls: UIURLs,
    ) -> None:
        """Initialize the notification message builder."""
        self.db_session = db_session
        self.workflow_token_service = workflow_token_service
        self.workflow_urls = workflow_urls
        self._event_builders: dict[type[NotificationEvent], NotificationBuilder] = {
            PasswordResetRequested: cast(
                "NotificationBuilder",
                self._build_password_reset,
            ),
            AccountVerificationRequested: cast(
                "NotificationBuilder",
                self._build_verification,
            ),
            EmailChangeRequested: cast(
                "NotificationBuilder",
                self._build_email_change,
            ),
            InviteCreated: cast("NotificationBuilder", self._build_invite),
        }
        if set(self._event_builders) != set(NOTIFICATION_EVENT_CLASSES):
            msg = "Notification builders must match the registered event classes"
            raise UnsupportedNotificationEventError(msg)

    def _build_link(self, url: str, token: str) -> str:
        """Append one opaque token to a validated workflow destination."""
        return f"{url}?{urlencode({'token': token})}"

    def _display_name(self, user: IdentityUserDTO) -> str:
        """Return the user's profile name, falling back to their email."""
        return f"{user.first_name} {user.last_name}".strip() or user.email

    async def _identity_and_email(
        self,
        *,
        public_id: UUID,
        user_email_id: int,
        status: UserEmailStatus,
    ) -> tuple[IdentityDTO, UserEmailDB] | None:
        """Load an identity only when the event still targets an active email."""
        row = (
            await self.db_session.execute(
                select(UserDB, OrganizationMembershipDB, OrganizationDB)
                .options(active_email_loader())
                .join(
                    OrganizationMembershipDB,
                    OrganizationMembershipDB.user_id == UserDB.id,
                )
                .join(
                    OrganizationDB,
                    OrganizationDB.id == OrganizationMembershipDB.organization_id,
                )
                .where(UserDB.public_id == public_id)
            )
        ).one_or_none()
        if row is None:
            return None
        target = next(
            (
                email
                for email in row[0].emails
                if email.id == user_email_id and email.status == status
            ),
            None,
        )
        if target is None:
            return None
        return to_identity(row), target

    async def build(self, event: NotificationEvent) -> TemplateEmail | None:
        """Build the notification represented by a supported outbox event."""
        builder = self._event_builders.get(type(event))
        if builder is None:
            msg = f"Unsupported notification event type: {event.event_type}"
            raise UnsupportedNotificationEventError(msg)
        return await builder(event)

    async def _build_password_reset(
        self, event: PasswordResetRequested
    ) -> TemplateEmail | None:
        """Build a password-reset message when its event is still actionable."""
        target = await self._identity_and_email(
            public_id=event.user_public_id,
            user_email_id=event.user_email_id,
            status=UserEmailStatus.CURRENT,
        )
        if target is None:
            return None
        identity, email = target
        if not identity.user.is_active or (
            identity.user.sessions_invalid_before is not None
            and event.occurred_at <= identity.user.sessions_invalid_before
        ):
            return None
        user = identity.user
        token = await self.workflow_token_service.issue_token_for_event(
            event_id=event.event_id,
            event_occurred_at=event.occurred_at,
            user_email_id=email.id,
            purpose=WorkflowTokenPurpose.RESET_PASSWORD,
        )
        if token is None:
            return None
        return TemplateEmail(
            subject="Reset your Zero Auth Lite password",
            to=[EmailAddress(email=email.email, name=self._display_name(user))],
            template_name="auth/reset_password.html",
            text_template_name="auth/reset_password.txt",
            context={
                "name": self._display_name(user),
                "reset_url": self._build_link(self.workflow_urls.password_reset, token),
            },
        )

    async def _build_verification(
        self, event: AccountVerificationRequested
    ) -> TemplateEmail | None:
        """Build an account-verification message for an active current email."""
        target = await self._identity_and_email(
            public_id=event.user_public_id,
            user_email_id=event.user_email_id,
            status=UserEmailStatus.CURRENT,
        )
        if target is None:
            return None
        identity, email = target
        if email.verified_at is not None or not identity.user.is_active:
            return None
        return await self._verification_message(
            event_id=event.event_id,
            event_occurred_at=event.occurred_at,
            user=identity.user,
            email=email,
            purpose=WorkflowTokenPurpose.VERIFY_EMAIL,
        )

    async def _build_email_change(
        self, event: EmailChangeRequested
    ) -> TemplateEmail | None:
        """Build an email-change message for an active pending address."""
        target = await self._identity_and_email(
            public_id=event.user_public_id,
            user_email_id=event.user_email_id,
            status=UserEmailStatus.PENDING,
        )
        if target is None:
            return None
        identity, email = target
        if not identity.user.is_active:
            return None
        return await self._verification_message(
            event_id=event.event_id,
            event_occurred_at=event.occurred_at,
            user=identity.user,
            email=email,
            purpose=WorkflowTokenPurpose.EMAIL_CHANGE,
        )

    async def _verification_message(
        self,
        *,
        event_id: str,
        event_occurred_at: datetime,
        user: IdentityUserDTO,
        email: UserEmailDB,
        purpose: WorkflowTokenPurpose,
    ) -> TemplateEmail | None:
        """Issue a verification token and build its corresponding message."""
        token = await self.workflow_token_service.issue_token_for_event(
            event_id=event_id,
            event_occurred_at=event_occurred_at,
            user_email_id=email.id,
            purpose=purpose,
        )
        if token is None:
            return None
        return TemplateEmail(
            subject="Verify your new Zero Auth Lite email"
            if purpose == WorkflowTokenPurpose.EMAIL_CHANGE
            else "Verify your Zero Auth Lite email",
            to=[EmailAddress(email=email.email, name=self._display_name(user))],
            template_name="auth/verify_email.html",
            text_template_name="auth/verify_email.txt",
            context={
                "name": self._display_name(user),
                "verify_url": self._build_link(self.workflow_urls.verification, token),
            },
        )

    async def _build_invite(self, event: InviteCreated) -> TemplateEmail | None:
        """Build an organization invitation while the target remains active."""
        target = await self._identity_and_email(
            public_id=event.user_public_id,
            user_email_id=event.user_email_id,
            status=UserEmailStatus.CURRENT,
        )
        if target is None:
            return None
        identity, email = target
        if (
            not identity.user.is_active
            or not identity.user.invitation_pending
            or email.verified_at is not None
            or (
                identity.user.sessions_invalid_before is not None
                and event.occurred_at <= identity.user.sessions_invalid_before
            )
        ):
            return None
        user, organization = identity.user, identity.organization
        token = await self.workflow_token_service.issue_token_for_event(
            event_id=event.event_id,
            event_occurred_at=event.occurred_at,
            user_email_id=email.id,
            purpose=WorkflowTokenPurpose.INVITE,
        )
        if token is None:
            return None
        return TemplateEmail(
            subject=f"Join {organization.name}",
            to=[EmailAddress(email=email.email, name=self._display_name(user))],
            template_name="organizations/invite.html",
            text_template_name="organizations/invite.txt",
            context={
                "name": self._display_name(user),
                "organization_name": organization.name,
                "invite_url": self._build_link(self.workflow_urls.invitation, token),
            },
        )
