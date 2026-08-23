"""Domain events for authentication and user notification workflows."""

from typing import Literal

from app.events.base import BaseEvent
from app.public_ids import PublicId


class PasswordResetRequested(BaseEvent):
    """A password reset was requested without revealing account existence."""

    event_type: Literal["auth.password_reset_requested"] = (
        "auth.password_reset_requested"
    )
    user_public_id: PublicId
    user_email_id: int


class AccountVerificationRequested(BaseEvent):
    """An account verification email was requested."""

    event_type: Literal["auth.account_verification_requested"] = (
        "auth.account_verification_requested"
    )
    user_public_id: PublicId
    user_email_id: int


class EmailChangeRequested(BaseEvent):
    """A verified user requested confirmation for a pending email address."""

    event_type: Literal["auth.email_change_requested"] = "auth.email_change_requested"
    user_public_id: PublicId
    user_email_id: int


class InviteCreated(BaseEvent):
    """An invite notification should be sent for a user."""

    event_type: Literal["auth.invite_created"] = "auth.invite_created"
    user_public_id: PublicId
    user_email_id: int
    inviter_name: str | None = None
