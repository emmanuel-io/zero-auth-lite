"""Tests for SMTP provider transport and message construction."""

import ssl
from unittest.mock import patch

import pytest
from app.mail.errors import MailDeliveryError
from app.mail.schemas import EmailAddress, EmailMessage
from app.mail.settings import MailSettings
from app.mail.smtp import SMTPMailProvider


pytestmark = pytest.mark.unit


def _message() -> EmailMessage:
    """Build a minimal message for SMTP transport tests."""
    return EmailMessage(
        subject="Subject",
        to=[EmailAddress(email="recipient@example.com")],
        text_body="Plain",
    )


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


def test_smtp_provider_translates_transport_failures() -> None:
    """Preserve the transport cause behind the stable delivery error."""
    provider = SMTPMailProvider(settings=MailSettings())
    with (
        patch("app.mail.smtp.smtplib.SMTP", side_effect=OSError("unavailable")),
        pytest.raises(MailDeliveryError) as exc_info,
    ):
        provider._send_sync(_message())  # noqa: SLF001

    assert isinstance(exc_info.value.__cause__, OSError)


def test_smtp_ssl_uses_a_verifying_tls_context() -> None:
    """Require certificate and hostname verification for implicit SMTP TLS."""
    provider = SMTPMailProvider(settings=MailSettings(smtp_ssl=True))

    with patch("app.mail.smtp.smtplib.SMTP_SSL") as smtp_ssl:
        provider._send_sync(_message())  # noqa: SLF001

    context = smtp_ssl.call_args.kwargs["context"]
    assert isinstance(context, ssl.SSLContext)
    assert context.verify_mode is ssl.CERT_REQUIRED
    assert context.check_hostname is True


def test_smtp_starttls_uses_a_verifying_tls_context() -> None:
    """Require certificate and hostname verification for SMTP STARTTLS."""
    provider = SMTPMailProvider(settings=MailSettings(smtp_starttls=True))

    with patch("app.mail.smtp.smtplib.SMTP") as smtp:
        provider._send_sync(_message())  # noqa: SLF001

    context = smtp.return_value.__enter__.return_value.starttls.call_args.kwargs[
        "context"
    ]
    assert isinstance(context, ssl.SSLContext)
    assert context.verify_mode is ssl.CERT_REQUIRED
    assert context.check_hostname is True


def test_smtp_provider_reuses_one_tls_context() -> None:
    """Load the system trust store once for all sends by one provider."""
    with patch(
        "app.mail.smtp.ssl.create_default_context",
        wraps=ssl.create_default_context,
    ) as create_context:
        provider = SMTPMailProvider(settings=MailSettings(smtp_starttls=True))
        with patch("app.mail.smtp.smtplib.SMTP"):
            provider._send_sync(_message())  # noqa: SLF001
            provider._send_sync(_message())  # noqa: SLF001

    create_context.assert_called_once_with()


def test_plain_smtp_does_not_create_a_tls_context() -> None:
    """Avoid loading certificate authorities when TLS is not configured."""
    with patch("app.mail.smtp.ssl.create_default_context") as create_context:
        provider = SMTPMailProvider(settings=MailSettings())
        with patch("app.mail.smtp.smtplib.SMTP"):
            provider._send_sync(_message())  # noqa: SLF001

    create_context.assert_not_called()
