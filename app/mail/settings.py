"""Schemas and settings for transactional email."""

from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field, SecretStr

from app.core.types import EmailValue


class MailSettings(BaseModel):
    """Transactional mail settings loaded from application configuration."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    enabled: bool = True
    default_from_email: EmailValue = "zero-auth-lite@example.com"
    default_from_name: str | None = "Zero Auth Lite"
    reply_to_email: EmailValue | None = None
    template_dir: Path | None = None
    smtp_host: str = "localhost"
    smtp_port: int = Field(default=1025, ge=1, le=65535)
    smtp_username: str | None = None
    smtp_password: SecretStr | None = None
    smtp_starttls: bool = False
    smtp_ssl: bool = False
    smtp_timeout_seconds: float = Field(default=10.0, gt=0)
