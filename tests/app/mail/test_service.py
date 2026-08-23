"""Tests for transactional mail service behavior."""

from pathlib import Path

import pytest
from app.mail.renderer import EmailTemplateRenderer
from app.mail.schemas import (
    EmailAddress,
    EmailMessage,
    TemplateEmail,
)
from app.mail.service import MailService
from app.mail.settings import MailSettings


pytestmark = pytest.mark.unit


class FakeMailProvider:
    """In-memory mail provider used by service tests."""

    def __init__(self) -> None:
        """Initialize an empty sent-message list."""
        self.sent: list[EmailMessage] = []

    async def send(self, message: EmailMessage) -> None:
        """Record a sent message.

        Args:
            message (EmailMessage): Message sent by the service.
        """
        self.sent.append(message)


@pytest.mark.asyncio
async def test_send_template_renders_html_and_plain_text_fallback(
    tmp_path: Path,
) -> None:
    """Assert templated sends render HTML and derive text when omitted."""
    template = tmp_path / "hello.html"
    template.write_text("<h1>Hello {{ name }}</h1>", encoding="utf-8")
    provider = FakeMailProvider()
    service = MailService(
        provider=provider,
        renderer=EmailTemplateRenderer(tmp_path),
        settings=MailSettings(),
    )

    await service.send_template(
        TemplateEmail(
            subject="Welcome",
            to=[EmailAddress(email="user@example.com")],
            template_name="hello.html",
            context={"name": "Ada"},
        )
    )

    assert len(provider.sent) == 1
    assert provider.sent[0].html_body == "<h1>Hello Ada</h1>"
    assert provider.sent[0].text_body == "Hello Ada"


@pytest.mark.asyncio
async def test_send_message_skips_delivery_when_disabled() -> None:
    """Assert disabled mail settings suppress provider delivery."""
    provider = FakeMailProvider()
    service = MailService(
        provider=provider,
        renderer=EmailTemplateRenderer(),
        settings=MailSettings(enabled=False),
    )

    await service.send_message(
        EmailMessage(
            subject="Quiet",
            to=[EmailAddress(email="user@example.com")],
            text_body="No delivery",
        )
    )

    assert provider.sent == []
