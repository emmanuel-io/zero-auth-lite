"""Authentication mail rendering, delivery, and provider factory."""

from typing import Protocol

from app.mail.renderer import EmailTemplateRenderer
from app.mail.schemas import EmailMessage, TemplateEmail
from app.mail.settings import MailSettings
from app.mail.smtp import SMTPMailProvider


class MailProvider(Protocol):
    """Transport contract accepted by the canonical mail service."""

    async def send(self, message: EmailMessage) -> None:
        """Deliver one fully rendered email message."""


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
        """Initialize the mail service."""
        self.provider = provider
        self.renderer = renderer
        self.settings = settings

    async def send_message(self, message: EmailMessage) -> None:
        """Send a provider-agnostic email outside the SQL transaction."""
        if not self.settings.enabled:
            return
        await self.provider.send(message)

    async def send_template(self, email: TemplateEmail) -> None:
        """Render and send a templated authentication email."""
        if not self.settings.enabled:
            return
        html_body = self.renderer.render(email.template_name, email.context)
        text_body = email.text_body
        if text_body is None and email.text_template_name is not None:
            text_body = self.renderer.render(email.text_template_name, email.context)
        if text_body is None:
            text_body = self.renderer.html_to_text(html_body)
        await self.send_message(
            EmailMessage(
                subject=email.subject,
                to=email.to,
                html_body=html_body,
                text_body=text_body,
                from_email=email.from_email,
                reply_to=email.reply_to,
            )
        )


def build_mail_provider(settings: MailSettings) -> SMTPMailProvider:
    """Build the configured mail delivery provider."""
    return SMTPMailProvider(settings)


def build_mail_service(settings: MailSettings) -> MailService:
    """Build one configured rendering and delivery service."""
    return MailService(
        provider=build_mail_provider(settings),
        renderer=EmailTemplateRenderer(settings.template_dir),
        settings=settings,
    )
