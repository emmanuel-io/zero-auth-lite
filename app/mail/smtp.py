"""SMTP transactional mail provider."""

import asyncio
import smtplib
from email.message import EmailMessage as StdlibEmailMessage
from email.utils import formataddr

from app.mail.errors import MailDeliveryError
from app.mail.schemas import EmailAddress, EmailMessage
from app.mail.settings import MailSettings


class SMTPMailProvider:
    """Send transactional email through SMTP."""

    def __init__(self, settings: MailSettings) -> None:
        """Initialize the provider with its SMTP connection settings."""
        self.settings = settings

    async def send(self, message: EmailMessage) -> None:
        """Send a message without blocking the application event loop.

        Raises:
            MailDeliveryError: If the SMTP server rejects delivery.
        """
        await asyncio.to_thread(self._send_sync, message)

    def _send_sync(self, message: EmailMessage) -> None:
        """Deliver a message through the configured synchronous SMTP client.

        Raises:
            MailDeliveryError: If connection, authentication, or sending fails.
        """
        mime_message = self._build_mime_message(message)
        recipients = [recipient.email for recipient in message.to]
        try:
            if self.settings.smtp_ssl:
                with smtplib.SMTP_SSL(
                    self.settings.smtp_host,
                    self.settings.smtp_port,
                    timeout=self.settings.smtp_timeout_seconds,
                ) as server:
                    self._authenticate(server)
                    server.send_message(mime_message, to_addrs=recipients)
                return
            with smtplib.SMTP(
                self.settings.smtp_host,
                self.settings.smtp_port,
                timeout=self.settings.smtp_timeout_seconds,
            ) as server:
                if self.settings.smtp_starttls:
                    server.starttls()
                self._authenticate(server)
                server.send_message(mime_message, to_addrs=recipients)
        except smtplib.SMTPException as exc:
            raise MailDeliveryError(str(exc)) from exc
        except OSError as exc:
            raise MailDeliveryError(str(exc)) from exc

    def _authenticate(self, server: smtplib.SMTP) -> None:
        """Authenticate when SMTP credentials are configured."""
        if not self.settings.smtp_username:
            return
        password = (
            self.settings.smtp_password.get_secret_value()
            if self.settings.smtp_password
            else ""
        )
        server.login(self.settings.smtp_username, password)

    def _build_mime_message(self, message: EmailMessage) -> StdlibEmailMessage:
        """Build the stdlib MIME representation of an application message."""
        mime_message = StdlibEmailMessage()
        from_email = message.from_email or EmailAddress(
            email=self.settings.default_from_email,
            name=self.settings.default_from_name,
        )
        mime_message["Subject"] = message.subject
        mime_message["From"] = self._format_address(from_email)
        mime_message["To"] = ", ".join(
            self._format_address(recipient) for recipient in message.to
        )
        reply_to = message.reply_to
        if reply_to is None and self.settings.reply_to_email is not None:
            reply_to = EmailAddress(email=self.settings.reply_to_email)
        if reply_to is not None:
            mime_message["Reply-To"] = self._format_address(reply_to)

        text_body = message.text_body or ""
        mime_message.set_content(text_body)
        if message.html_body is not None:
            mime_message.add_alternative(message.html_body, subtype="html")
        return mime_message

    def _format_address(self, address: EmailAddress) -> str:
        """Format an email address for an RFC-compatible message header."""
        return formataddr((address.name or "", str(address.email)))
