"""Settings for authentication email delivery."""

from pathlib import Path
from typing import Annotated

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    model_validator,
    SecretStr,
    StringConstraints,
)

from app.core.types import EmailValue
from app.mail.schemas import EmailHeaderValue


SMTPHost = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1)]
DEFAULT_MAIL_FROM_EMAIL = "zero-auth-lite@example.com"


class MailSettings(BaseModel):
    """Mail delivery settings loaded from application configuration."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    enabled: bool = True
    default_from_email: EmailValue = DEFAULT_MAIL_FROM_EMAIL
    default_from_name: EmailHeaderValue | None = "Zero Auth Lite"
    reply_to_email: EmailValue | None = None
    template_dir: Path | None = None
    smtp_host: SMTPHost = "localhost"
    smtp_port: int = Field(default=1025, ge=1, le=65535)
    smtp_username: str | None = None
    smtp_password: SecretStr | None = None
    smtp_starttls: bool = False
    smtp_ssl: bool = False
    smtp_timeout_seconds: float = Field(default=10.0, gt=0)

    @model_validator(mode="after")
    def validate_smtp_transport(self) -> "MailSettings":
        """Reject ambiguous TLS and authentication configuration."""
        if self.smtp_ssl and self.smtp_starttls:
            msg = "SMTP SSL and STARTTLS are mutually exclusive"
            raise ValueError(msg)

        username_configured = self.smtp_username is not None
        password_configured = self.smtp_password is not None
        if username_configured != password_configured:
            msg = "SMTP username and password must be configured together"
            raise ValueError(msg)
        if self.smtp_username is not None and not self.smtp_username.strip():
            msg = "SMTP username must not be empty"
            raise ValueError(msg)
        if self.smtp_password is not None and not self.smtp_password.get_secret_value():
            msg = "SMTP password must not be empty"
            raise ValueError(msg)
        if username_configured and not (self.smtp_ssl or self.smtp_starttls):
            msg = "SMTP authentication requires SSL or STARTTLS"
            raise ValueError(msg)
        return self
