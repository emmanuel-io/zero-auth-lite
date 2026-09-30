"""Tests for transactional-mail settings."""

import pytest
from app.mail.settings import MailSettings
from pydantic import ValidationError


pytestmark = pytest.mark.unit


def test_smtp_tls_modes_are_mutually_exclusive() -> None:
    """Reject a transport that requests two incompatible TLS handshakes."""
    with pytest.raises(ValidationError, match="mutually exclusive"):
        MailSettings(smtp_ssl=True, smtp_starttls=True)


@pytest.mark.parametrize(
    ("username", "password"),
    [
        ("mailer", None),
        (None, "secret"),
        ("", "secret"),
        ("mailer", ""),
    ],
)
def test_smtp_credentials_must_be_a_nonempty_pair(
    username: str | None, password: str | None
) -> None:
    """Reject incomplete or empty SMTP authentication credentials."""
    with pytest.raises(ValidationError, match=r"SMTP (username|password)"):
        MailSettings(smtp_username=username, smtp_password=password)


def test_smtp_credentials_accept_a_complete_pair() -> None:
    """Accept an explicit nonempty SMTP username and password."""
    settings = MailSettings(
        smtp_username="mailer",
        smtp_password="secret",  # noqa: S106
        smtp_starttls=True,
    )

    assert settings.smtp_username == "mailer"
    assert settings.smtp_password is not None
    assert settings.smtp_password.get_secret_value() == "secret"


def test_smtp_credentials_require_tls() -> None:
    """Never permit SMTP authentication over a plaintext connection."""
    with pytest.raises(ValidationError, match="requires SSL or STARTTLS"):
        MailSettings(
            smtp_username="mailer",
            smtp_password="secret",  # noqa: S106
        )


@pytest.mark.parametrize("smtp_host", ["", "   "])
def test_smtp_host_must_not_be_blank(smtp_host: str) -> None:
    """Reject an SMTP destination that cannot be resolved."""
    with pytest.raises(ValidationError, match="smtp_host"):
        MailSettings(smtp_host=smtp_host)


def test_smtp_host_is_trimmed() -> None:
    """Normalize accidental surrounding whitespace in the SMTP hostname."""
    assert MailSettings(smtp_host=" mail.example ").smtp_host == "mail.example"


@pytest.mark.parametrize("name", ["Zero Auth\nLite", "Zero Auth\rLite"])
def test_default_sender_name_rejects_line_breaks(name: str) -> None:
    """Reject sender names that cannot be represented as one mail header."""
    with pytest.raises(ValidationError):
        MailSettings(default_from_name=name)
