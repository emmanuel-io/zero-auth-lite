"""Tests for SMTP provider message construction."""

import pytest
from app.mail.schemas import EmailAddress, EmailMessage
from app.mail.settings import MailSettings
from app.mail.smtp import SMTPMailProvider


pytestmark = pytest.mark.unit


def test_smtp_provider_builds_multipart_message() -> None:
    """Assert SMTP provider builds headers and multipart bodies."""
    provider = SMTPMailProvider(
        settings=MailSettings(
            default_from_email="sender@example.com",
            default_from_name="Zero Auth Lite",
            reply_to_email="support@example.com",
        )
    )

    message = provider._build_mime_message(  # noqa: SLF001
        EmailMessage(
            subject="Subject",
            to=[EmailAddress(email="recipient@example.com", name="Recipient")],
            text_body="Plain",
            html_body="<p>HTML</p>",
        )
    )

    assert message["Subject"] == "Subject"
    assert message["From"] == "Zero Auth Lite <sender@example.com>"
    assert message["To"] == "Recipient <recipient@example.com>"
    assert message["Reply-To"] == "support@example.com"
    assert message.is_multipart()
