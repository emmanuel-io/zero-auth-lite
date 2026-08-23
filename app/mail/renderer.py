"""Jinja rendering utilities for transactional email templates."""

from html.parser import HTMLParser
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape, TemplateError

from app.mail.errors import MailTemplateError


DEFAULT_EMAIL_TEMPLATE_DIR = (
    Path(__file__).resolve().parents[1] / "templates" / "emails"
)


class _PlainTextHTMLParser(HTMLParser):
    """HTML parser that extracts readable plain text from simple email markup."""

    def __init__(self) -> None:
        """Initialize the text collector."""
        super().__init__()
        self._parts: list[str] = []

    def handle_data(self, data: str) -> None:
        """Collect text nodes from the parsed HTML.

        Args:
            data (str): Text content found by the HTML parser.
        """
        stripped = data.strip()
        if stripped:
            self._parts.append(stripped)

    def handle_starttag(
        self,
        tag: str,
        attrs: list[tuple[str, str | None]],
    ) -> None:
        """Add spacing around block-level HTML tags.

        Args:
            tag (str): HTML tag name.
            attrs (list[tuple[str, str | None]]): HTML attributes.
        """
        del attrs
        if tag in {"br", "p", "div", "tr", "li", "h1", "h2", "h3"}:
            self._parts.append("\n")

    def text(self) -> str:
        """Return collected plain text with compact blank lines.

        Returns:
            str: Plain-text representation of parsed HTML.
        """
        lines = [line.strip() for line in " ".join(self._parts).splitlines()]
        return "\n".join(line for line in lines if line).strip()


class EmailTemplateRenderer:
    """Render transactional email templates from a filesystem directory."""

    def __init__(self, template_dir: Path | None = None) -> None:
        """Initialize a renderer with the configured template directory.

        Args:
            template_dir (Path | None): Directory containing email templates.
        """
        self.template_dir = template_dir or DEFAULT_EMAIL_TEMPLATE_DIR
        self.environment = Environment(
            loader=FileSystemLoader(str(self.template_dir)),
            autoescape=select_autoescape(("html", "xml")),
        )

    def render(self, template_name: str, context: dict[str, object]) -> str:
        """Render a template with the provided context.

        Args:
            template_name (str): Template path relative to the email template root.
            context (dict[str, object]): Values available inside the template.

        Returns:
            str: Rendered template output.

        Raises:
            MailTemplateError: If Jinja cannot load or render the template.
        """
        try:
            template = self.environment.get_template(template_name)
            return template.render(**context)
        except TemplateError as exc:
            raise MailTemplateError(str(exc)) from exc

    def html_to_text(self, html: str) -> str:
        """Create a plain-text fallback from HTML.

        Args:
            html (str): Rendered HTML content.

        Returns:
            str: Plain-text fallback content.
        """
        parser = _PlainTextHTMLParser()
        parser.feed(html)
        return parser.text()
