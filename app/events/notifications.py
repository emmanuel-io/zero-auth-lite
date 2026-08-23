"""Build canonical-server authentication notification emails."""

from datetime import datetime
from urllib.parse import urlencode

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth_tokens.enums import AuthTokenPurpose
from app.auth_tokens.service import AuthTokenService
from app.db.models.organization import OrganizationDB
from app.db.models.organization_membership import OrganizationMembershipDB
from app.db.models.user import UserDB, UserEmailDB
from app.events.base import BaseEvent
from app.events.types import (
    AccountVerificationRequested,
    EmailChangeRequested,
    InviteCreated,
    PasswordResetRequested,
)
from app.identity.dtos import IdentityDTO, IdentityUserDTO
from app.identity.mapping import to_identity
from app.identity.users.emails import active_email_loader
from app.identity.users.enums import UserEmailStatus
from app.mail.schemas import EmailAddress, TemplateEmail
from app.public_ids import PublicId
from app.settings.auth import AuthEmailSettings


class AuthNotificationService:
    """Prepare retry-safe notification messages without sending them."""

    def __init__(
        self,
        *,
        db_session: AsyncSession,
        auth_token_service: AuthTokenService,
        settings: AuthEmailSettings,
    ) -> None:
        """Initialize the notification message builder."""
        self.db_session = db_session
        self.auth_token_service = auth_token_service
        self.settings = settings

    def _frontend_base_url(self) -> str:
        return str(self.settings.frontend_base_url).rstrip("/")

    def _build_link(self, path: str, token: str) -> str:
        return f"{self._frontend_base_url()}{path}?{urlencode({'token': token})}"

    def _display_name(self, user: IdentityUserDTO) -> str:
        return f"{user.first_name} {user.last_name}".strip() or user.email

    async def _identity_and_email(
        self,
        *,
        public_id: PublicId,
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
                .where(UserDB.public_id == int(public_id))
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

    async def build(self, event: BaseEvent) -> TemplateEmail | None:
        """Build the notification represented by a supported outbox event."""
        if isinstance(event, PasswordResetRequested):
            return await self._build_password_reset(event)
        if isinstance(event, AccountVerificationRequested):
            return await self._build_verification(event)
        if isinstance(event, EmailChangeRequested):
            return await self._build_email_change(event)
        if isinstance(event, InviteCreated):
            return await self._build_invite(event)
        return None

    async def _build_password_reset(
        self, event: PasswordResetRequested
    ) -> TemplateEmail | None:
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
        token = await self.auth_token_service.issue_token_for_event(
            event_id=event.event_id,
            event_occurred_at=event.occurred_at,
            user_email_id=email.id,
            purpose=AuthTokenPurpose.reset_password,
        )
        if token is None:
            return None
        return TemplateEmail(
            subject="Reset your Zero Auth Lite password",
            to=[EmailAddress(email=email.email, name=self._display_name(user))],
            template_name="auth/reset_password.html",
            context={
                "name": self._display_name(user),
                "reset_url": self._build_link("/reset-password", token),
            },
        )

    async def _build_verification(
        self, event: AccountVerificationRequested
    ) -> TemplateEmail | None:
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
            purpose=AuthTokenPurpose.verify_email,
        )

    async def _build_email_change(
        self, event: EmailChangeRequested
    ) -> TemplateEmail | None:
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
            purpose=AuthTokenPurpose.email_change,
        )

    async def _verification_message(
        self,
        *,
        event_id: str,
        event_occurred_at: datetime,
        user: IdentityUserDTO,
        email: UserEmailDB,
        purpose: AuthTokenPurpose,
    ) -> TemplateEmail | None:
        token = await self.auth_token_service.issue_token_for_event(
            event_id=event_id,
            event_occurred_at=event_occurred_at,
            user_email_id=email.id,
            purpose=purpose,
        )
        if token is None:
            return None
        return TemplateEmail(
            subject="Verify your new Zero Auth Lite email"
            if purpose == AuthTokenPurpose.email_change
            else "Verify your Zero Auth Lite email",
            to=[EmailAddress(email=email.email, name=self._display_name(user))],
            template_name="auth/verify_email.html",
            context={
                "name": self._display_name(user),
                "verify_url": self._build_link("/verify-email", token),
            },
        )

    async def _build_invite(self, event: InviteCreated) -> TemplateEmail | None:
        target = await self._identity_and_email(
            public_id=event.user_public_id,
            user_email_id=event.user_email_id,
            status=UserEmailStatus.CURRENT,
        )
        if target is None:
            return None
        identity, email = target
        if not identity.user.is_active:
            return None
        user, organization = identity.user, identity.organization
        token = await self.auth_token_service.issue_token_for_event(
            event_id=event.event_id,
            event_occurred_at=event.occurred_at,
            user_email_id=email.id,
            purpose=AuthTokenPurpose.invite,
        )
        if token is None:
            return None
        return TemplateEmail(
            subject=f"Join {organization.name}",
            to=[EmailAddress(email=email.email, name=self._display_name(user))],
            template_name="organizations/invite.html",
            context={
                "name": self._display_name(user),
                "organization_name": organization.name,
                "inviter_name": event.inviter_name or "An administrator",
                "invite_url": self._build_link("/accept-invite", token),
            },
        )
