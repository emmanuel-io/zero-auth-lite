"""Tests for CSRF on ordinary server-rendered forms."""

from types import SimpleNamespace

import pytest
from app.browser_sessions.errors import (
    CSRFCookieHeaderMismatchError,
    CSRFFormOriginMismatchError,
)
from app.browser_sessions.form_csrf import validate_pre_session_form_csrf
from app.browser_sessions.settings import CSRFSettings
from starlette.requests import Request


pytestmark = pytest.mark.unit


def _request(
    *, cookie_header: str, origin: str | None = "http://localhost:8000"
) -> Request:
    """Build a same-origin form request with its raw Cookie header."""
    headers = [(b"cookie", cookie_header.encode())]
    if origin is not None:
        headers.insert(0, (b"origin", origin.encode()))
    return Request(
        {
            "type": "http",
            "app": SimpleNamespace(state=SimpleNamespace()),
            "method": "POST",
            "path": "/login",
            "headers": headers,
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


@pytest.mark.negative
@pytest.mark.parametrize("origin", [None, "not-a-url", "https://evil.test"])
def test_form_csrf_translates_request_source_failures(origin: str | None) -> None:
    """Present absent and untrusted request sources as form-origin failures."""
    settings = CSRFSettings(cookie_secure=False)

    with pytest.raises(CSRFFormOriginMismatchError):
        validate_pre_session_form_csrf(
            request=_request(cookie_header="csrftoken-form=current", origin=origin),
            csrf_token="current",  # noqa: S106
            csrf_settings=settings,
        )


@pytest.mark.negative
def test_form_csrf_preserves_cookie_token_mismatch() -> None:
    """Do not mislabel a token mismatch as a request-origin failure."""
    with pytest.raises(CSRFCookieHeaderMismatchError):
        validate_pre_session_form_csrf(
            request=_request(cookie_header="csrftoken-form=stored"),
            csrf_token="submitted",  # noqa: S106
            csrf_settings=CSRFSettings(cookie_secure=False),
        )
