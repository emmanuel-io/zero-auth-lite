"""Schemas and settings for transactional email."""

from pydantic import BaseModel, Field

from app.core.types import EmailValue


class EmailAddress(BaseModel):
    """Email address with an optional display name."""

    email: EmailValue
    name: str | None = None


class EmailMessage(BaseModel):
    """Provider-agnostic transactional email message."""

    subject: str = Field(min_length=1)
    to: list[EmailAddress] = Field(min_length=1)
    html_body: str | None = None
    text_body: str | None = None
    from_email: EmailAddress | None = None
    reply_to: EmailAddress | None = None


class TemplateEmail(BaseModel):
    """Input for rendering and sending a templated email."""

    subject: str = Field(min_length=1)
    to: list[EmailAddress] = Field(min_length=1)
    template_name: str = Field(min_length=1)
    context: dict[str, object] = Field(default_factory=dict)
    text_template_name: str | None = None
    text_body: str | None = None
    from_email: EmailAddress | None = None
    reply_to: EmailAddress | None = None
