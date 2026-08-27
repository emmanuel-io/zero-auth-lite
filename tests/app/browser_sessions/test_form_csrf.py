"""Tests for CSRF on ordinary server-rendered forms."""

from types import SimpleNamespace

import pytest
from app.browser_sessions.form_csrf import validate_pre_session_form_csrf
from app.browser_sessions.settings import CSRFSettings
from starlette.requests import Request


pytestmark = pytest.mark.unit


def _request(*, cookie_header: str) -> Request:
    """Build a same-origin form request with its raw Cookie header."""
    return Request(
        {
            "type": "http",
            "app": SimpleNamespace(state=SimpleNamespace()),
            "method": "POST",
            "path": "/login",
            "headers": [
                (b"origin", b"http://localhost:8000"),
                (b"cookie", cookie_header.encode()),
            ],
            "scheme": "http",
            "server": ("localhost", 8000),
            "query_string": b"",
        }
    )


def test_form_csrf_accepts_any_same_named_cookie_sent_by_the_browser() -> None:
    """Handle stale domain/path duplicates without trusting only one collapsed value."""
    settings = CSRFSettings(
        cookie_secure=False,
        cookie_domain="",
        public_origin="http://localhost:8000",
        trusted_origins=("http://localhost:8000",),
    )

    validate_pre_session_form_csrf(
        request=_request(cookie_header="csrftoken-form=stale; csrftoken-form=current"),
        csrf_token="current",  # noqa: S106
        csrf_settings=settings,
    )
