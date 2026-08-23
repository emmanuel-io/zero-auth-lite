"""Test collaborators for authentication workflow API adapters."""

VERIFY_TOKEN = "verify-token-value"  # noqa: S105
CHANGE_TOKEN = "change-token-value"  # noqa: S105
RESET_TOKEN = "reset-token-value"  # noqa: S105
INVITE_TOKEN = "invite-token-value"  # noqa: S105
NEW_PASSWORD = "NewPass1!"  # noqa: S105


class FakeAuthTokenConfirmationService:
    """Capture token confirmation requests from HTTP adapters."""

    def __init__(self) -> None:
        """Initialize empty token captures."""
        self.registered_email_token: str | None = None
        self.email_change_token: str | None = None
        self.reset_token: str | None = None
        self.invite_token: str | None = None

    async def confirm_registered_email(self, token: str) -> None:
        """Record a self-registration verification token."""
        self.registered_email_token = token

    async def confirm_email_change(self, token: str) -> None:
        """Record an email-change confirmation token."""
        self.email_change_token = token

    async def reset_password(self, *, token: str, password: str) -> None:
        """Record a password-reset token."""
        del password
        self.reset_token = token

    async def accept_invite(self, *, token: str, password: str) -> None:
        """Record an invitation token."""
        del password
        self.invite_token = token


class FakeAuthNotificationRequestService:
    """Capture resolved authentication notification requests."""

    def __init__(self) -> None:
        """Initialize empty request storage."""
        self.verification_emails: list[str] = []
        self.password_reset_emails: list[str] = []

    async def request_account_verification(self, email: str) -> None:
        """Record one verification request."""
        self.verification_emails.append(email)

    async def request_password_reset(self, email: str) -> None:
        """Record one password-reset request."""
        self.password_reset_emails.append(email)
