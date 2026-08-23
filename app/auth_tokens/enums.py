"""Enumerations for single-use authentication tokens."""

from enum import StrEnum


class AuthTokenPurpose(StrEnum):
    """Supported single-use authentication token purposes."""

    verify_email = "verify_email"
    email_change = "email_change"
    invite = "invite"
    reset_password = "reset_password"  # noqa: S105
