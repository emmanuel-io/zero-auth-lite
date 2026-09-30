"""Tests for mail delivery schema invariants."""

import pytest
from app.mail.schemas import EmailAddress, EmailMessage, TemplateEmail
from pydantic import ValidationError


pytestmark = pytest.mark.unit


def test_email_message_requires_a_body() -> None:
    """Reject incomplete messages before they reach the mail service."""
    with pytest.raises(ValidationError, match="HTML or text body"):
        EmailMessage(
            subject="Empty",
            to=[EmailAddress(email="user@example.com")],
        )


@pytest.mark.parametrize(
    "subject",
    ["First line\nSecond line", "First line\rSecond line"],
)
def test_email_subject_rejects_line_breaks(subject: str) -> None:
    """Reject values that cannot be represented as one email header."""
    with pytest.raises(ValidationError):
        TemplateEmail(
            subject=subject,
            to=[EmailAddress(email="user@example.com")],
            template_name="message.html",
        )


@pytest.mark.parametrize("name", ["First\nLast", "First\rLast"])
def test_email_display_name_rejects_line_breaks(name: str) -> None:
    """Reject invalid address display names at the mail schema boundary."""
    with pytest.raises(ValidationError):
        EmailAddress(email="user@example.com", name=name)
