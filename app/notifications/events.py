"""Domain events for authentication and user notification workflows."""

from typing import Literal
from uuid import UUID

from app.notifications.event import NotificationEvent


class PasswordResetRequested(NotificationEvent):
    """A password reset was requested without revealing account existence."""

    event_type: Literal["auth.password_reset_requested"] = (
        "auth.password_reset_requested"
    )
    user_public_id: UUID
    user_email_id: int


class AccountVerificationRequested(NotificationEvent):
    """An account verification email was requested."""

    event_type: Literal["auth.account_verification_requested"] = (
        "auth.account_verification_requested"
    )
    user_public_id: UUID
    user_email_id: int


class EmailChangeRequested(NotificationEvent):
    """A verified user requested confirmation for a pending email address."""

    event_type: Literal["auth.email_change_requested"] = "auth.email_change_requested"
    user_public_id: UUID
    user_email_id: int


class InviteCreated(NotificationEvent):
    """An invite notification should be sent for a user."""

    event_type: Literal["auth.invite_created"] = "auth.invite_created"
    user_public_id: UUID
    user_email_id: int


NOTIFICATION_EVENT_CLASSES: tuple[type[NotificationEvent], ...] = (
    PasswordResetRequested,
    AccountVerificationRequested,
    EmailChangeRequested,
    InviteCreated,
)
NOTIFICATION_EVENT_REGISTRY: dict[str, type[NotificationEvent]] = {
    event_class.model_fields["event_type"].default: event_class
    for event_class in NOTIFICATION_EVENT_CLASSES
}
