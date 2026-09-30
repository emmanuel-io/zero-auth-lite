"""Tests for browser-session transport settings."""

import pytest
from app.browser_sessions.settings import BrowserSessionSettings, CSRFSettings
from pydantic import ValidationError


pytestmark = pytest.mark.unit


@pytest.mark.negative
@pytest.mark.parametrize("cookie_name", ["", "has space", "semi;colon", "path/name"])
def test_cookie_names_must_use_http_token_characters(cookie_name: str) -> None:
    """Reject names that cannot identify an HTTP cookie safely."""
    with pytest.raises(ValidationError):
        CSRFSettings(cookie_name=cookie_name)


@pytest.mark.negative
@pytest.mark.parametrize("session_cookie_name", ["csrf", "csrf-form"])
def test_session_cookie_name_must_not_collide_with_csrf_cookies(
    session_cookie_name: str,
) -> None:
    """Reject settings where one response would overwrite another cookie."""
    with pytest.raises(ValidationError, match="cookie names must be distinct"):
        BrowserSessionSettings(
            cookie_name=session_cookie_name,
            csrf=CSRFSettings(cookie_name="csrf"),
        )


def test_form_csrf_cookie_name_is_derived_from_csrf_settings() -> None:
    """Keep the anonymous-form cookie namespace explicit in configuration."""
    assert CSRFSettings(cookie_name="custom-csrf").form_cookie_name == (
        "custom-csrf-form"
    )
