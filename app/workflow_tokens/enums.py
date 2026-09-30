"""Enumerations for single-use workflow tokens."""

from enum import StrEnum


class WorkflowTokenPurpose(StrEnum):
    """Supported single-use workflow token purposes."""

    VERIFY_EMAIL = "verify_email"
    EMAIL_CHANGE = "email_change"
    INVITE = "invite"
    RESET_PASSWORD = "reset_password"  # noqa: S105
