"""Tests for email template rendering."""

from pathlib import Path

import pytest
from app.mail.errors import MailTemplateError
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


@pytest.mark.parametrize(
    ("template_name", "context", "workflow_url"),
    [
        (
            "auth/reset_password.txt",
            {"name": "Ada", "reset_url": "https://example.test/reset"},
            "https://example.test/reset",
        ),
        (
            "auth/verify_email.txt",
            {"name": "Ada", "verify_url": "https://example.test/verify"},
            "https://example.test/verify",
        ),
        (
            "organizations/invite.txt",
            {
                "name": "Ada",
                "organization_name": "Example",
                "invite_url": "https://example.test/invite",
            },
            "https://example.test/invite",
        ),
    ],
)
def test_packaged_text_templates_include_workflow_url(
    template_name: str,
    context: dict[str, object],
    workflow_url: str,
) -> None:
    """Keep actionable links visible in plain-text workflow messages."""
    renderer = EmailTemplateRenderer()

    text = renderer.render(template_name, context)

    assert workflow_url in text


def test_renderer_uses_custom_template_directory(tmp_path: Path) -> None:
    """Assert callers may override the email template directory."""
    template = tmp_path / "custom.html"
    template.write_text("Hello {{ name }}", encoding="utf-8")
    renderer = EmailTemplateRenderer(tmp_path)

    assert renderer.render("custom.html", {"name": "Grace"}) == "Hello Grace"


def test_renderer_rejects_missing_template_context(tmp_path: Path) -> None:
    """Fail before delivery when a required template value is absent."""
    template = tmp_path / "custom.html"
    template.write_text("Open {{ workflow_url }}", encoding="utf-8")
    renderer = EmailTemplateRenderer(tmp_path)

    with pytest.raises(MailTemplateError):
        renderer.render("custom.html", {})


def test_renderer_preserves_explicit_optional_defaults(tmp_path: Path) -> None:
    """Allow templates to declare an intentional fallback for optional values."""
    template = tmp_path / "custom.html"
    template.write_text('{{ name | default("there") }}', encoding="utf-8")
    renderer = EmailTemplateRenderer(tmp_path)

    assert renderer.render("custom.html", {}) == "there"


def test_renderer_translates_template_failures_without_exposing_details(
    tmp_path: Path,
) -> None:
    """Raise the stable mail error while preserving the Jinja cause."""
    renderer = EmailTemplateRenderer(tmp_path)

    with pytest.raises(MailTemplateError) as exc_info:
        renderer.render("missing.html", {})

    assert str(exc_info.value) == (
        "[MAIL_TEMPLATE_ERROR] Mail template could not be rendered."
    )
    assert exc_info.value.__cause__ is not None
