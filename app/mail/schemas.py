"""Provider-agnostic schemas for authentication email delivery."""

from typing import Annotated, Self

from pydantic import BaseModel, Field, model_validator, StringConstraints

from app.core.types import EmailValue


EmailHeaderValue = Annotated[str, StringConstraints(pattern=r"^[^\r\n]*$")]
EmailSubject = Annotated[
    str,
    StringConstraints(min_length=1, pattern=r"^[^\r\n]*$"),
]


class EmailAddress(BaseModel):
    """Email address with an optional display name."""

    email: EmailValue
    name: EmailHeaderValue | None = None


class EmailMessage(BaseModel):
    """Provider-agnostic email message."""

    subject: EmailSubject
    to: list[EmailAddress] = Field(min_length=1)
    html_body: str | None = None
    text_body: str | None = None
    from_email: EmailAddress | None = None
    reply_to: EmailAddress | None = None

    @model_validator(mode="after")
    def require_body(self) -> Self:
        """Require at least one body before a message reaches a provider."""
        if self.html_body is None and self.text_body is None:
            msg = "Email message requires an HTML or text body"
            raise ValueError(msg)
        return self


class TemplateEmail(BaseModel):
    """Input for rendering and sending a templated email."""

    subject: EmailSubject
    to: list[EmailAddress] = Field(min_length=1)
    template_name: str = Field(min_length=1)
    context: dict[str, object] = Field(default_factory=dict)
    text_template_name: str | None = None
    text_body: str | None = None
    from_email: EmailAddress | None = None
    reply_to: EmailAddress | None = None
