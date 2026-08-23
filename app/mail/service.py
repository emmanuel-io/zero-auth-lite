"""Transactional mail service and provider factory."""

from collections.abc import Sequence
from typing import cast, Protocol

from app.mail.errors import MailConfigurationError
from app.mail.renderer import EmailTemplateRenderer
from app.mail.schemas import (
    EmailAddress,
    EmailMessage,
    TemplateEmail,
)
from app.mail.settings import MailSettings
from app.mail.smtp import SMTPMailProvider


class _EmailAddressLike(Protocol):
    """Address object shape accepted by the example mail adapter."""

    email: str
    name: str | None


class MailProvider(Protocol):
    """Transport contract accepted by the canonical mail service."""

    async def send(self, message: EmailMessage) -> None:
        """Deliver one fully rendered email message."""


def _email_address(address: object | None) -> EmailAddress | None:
    """Return an app email address from a compatible address object."""
    if address is None:
        return None
    if isinstance(address, EmailAddress):
        return address
    compatible_address = cast("_EmailAddressLike", address)
    return EmailAddress(
        email=str(compatible_address.email),
        name=compatible_address.name,
    )


def _email_addresses(addresses: Sequence[object]) -> list[EmailAddress]:
    """Return app email addresses from compatible address objects."""
    return [
        normalized
        for address in addresses
        if (normalized := _email_address(address)) is not None
    ]


class MailService:
    """Render and deliver mail after the outbox transaction commits.

    Zero Auth Lite ships :class:`SMTPMailProvider` as its canonical implementation.
    An embedding application can provide another transport by implementing the
    small :class:`MailProvider` contract; provider-specific integrations remain
    outside the canonical server.
    """

    def __init__(
        self,
        provider: MailProvider,
        renderer: EmailTemplateRenderer,
        settings: MailSettings,
    ) -> None:
        """Initialize the mail service.

        Args:
            provider (MailProvider): Configured mail transport.
            renderer (EmailTemplateRenderer): Template renderer.
            settings (MailSettings): Mail settings.
        """
        self.provider = provider
        self.renderer = renderer
        self.settings = settings

    async def send_message(self, message: EmailMessage) -> None:
        """Send a provider-agnostic email message outside the SQL transaction.

        Args:
            message (EmailMessage): Message to send.
        """
        if not self.settings.enabled:
            return
        if message.html_body is None and message.text_body is None:
            message_detail = "message body is required"
            raise MailConfigurationError(message_detail)
        await self.provider.send(message)

    async def send_template(self, email: TemplateEmail) -> None:
        """Render and send a templated transactional email.

        Args:
            email (TemplateEmail): Template send request.
        """
        html_body = self.renderer.render(email.template_name, email.context)
        text_body = email.text_body
        if text_body is None and email.text_template_name is not None:
            text_body = self.renderer.render(email.text_template_name, email.context)
        if text_body is None:
            text_body = self.renderer.html_to_text(html_body)
        await self.send_message(
            EmailMessage(
                subject=email.subject,
                to=_email_addresses(email.to),
                html_body=html_body,
                text_body=text_body,
                from_email=_email_address(email.from_email),
                reply_to=_email_address(email.reply_to),
            )
        )


def build_mail_provider(settings: MailSettings) -> SMTPMailProvider:
    """Build the configured transactional mail provider."""
    return SMTPMailProvider(settings)
