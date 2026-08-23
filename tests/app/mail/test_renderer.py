"""Tests for email template rendering."""

from pathlib import Path

import pytest
from app.mail.renderer import EmailTemplateRenderer


pytestmark = pytest.mark.unit


def test_renderer_renders_packaged_email_template() -> None:
    """Assert packaged templates render with caller-provided context."""
    renderer = EmailTemplateRenderer()

    html = renderer.render(
        "auth/verify_email.html",
        {"name": "Ada", "verify_url": "https://example.test/verify"},
    )

    assert "Ada" in html
    assert "https://example.test/verify" in html


def test_renderer_creates_text_fallback_from_html() -> None:
    """Assert the renderer can derive a plain text fallback."""
    renderer = EmailTemplateRenderer()

    text = renderer.html_to_text("<h1>Hello</h1><p>Open <a>dashboard</a></p>")

    assert "Hello" in text
    assert "Open" in text
    assert "dashboard" in text


def test_renderer_uses_custom_template_directory(tmp_path: Path) -> None:
    """Assert callers may override the email template directory."""
    template = tmp_path / "custom.html"
    template.write_text("Hello {{ name }}", encoding="utf-8")
    renderer = EmailTemplateRenderer(tmp_path)

    assert renderer.render("custom.html", {"name": "Grace"}) == "Hello Grace"
