"""Tests for browser-session CSRF helper functions."""

from http.cookies import SimpleCookie
from types import SimpleNamespace

import pytest
from app.browser_sessions.csrf import (
    validate_double_submit_csrf,
    validate_request_origin,
)
from app.browser_sessions.errors import (
    CSRFCookieHeaderMismatchError,
    CSRFMissingCookieError,
    CSRFMissingHeaderError,
)
from app.browser_sessions.settings import CSRFSettings
from app.core.compare import constant_time_equals
from starlette.requests import Request


pytestmark = pytest.mark.unit

CSRF_VALUE = "csrf-token"


def make_request(
    *,
    method: str = "POST",
    headers: dict[str, str] | None = None,
    cookies: dict[str, str] | None = None,
) -> Request:
    """Build a Starlette request for CSRF helper tests."""
    raw_headers = []
    for key, value in (headers or {}).items():
        raw_headers.append((key.lower().encode(), value.encode()))
    if cookies:
        cookie = SimpleCookie()
        for key, value in cookies.items():
            cookie[key] = value
        raw_headers.append(
            (b"cookie", cookie.output(header="", sep=";").strip().encode())
        )
    app = SimpleNamespace(state=SimpleNamespace())
    return Request(
        {
            "type": "http",
            "app": app,
            "method": method,
            "path": "/unit",
            "headers": raw_headers,
            "scheme": "https",
            "server": ("api.test", 443),
            "client": ("203.0.113.10", 50000),
            "query_string": b"",
        }
    )


def test_constant_time_equals_handles_missing_and_matching_values() -> None:
    """Assert CSRF token comparison rejects missing values and compares matches."""
    assert constant_time_equals(None, CSRF_VALUE) is False
    assert constant_time_equals(CSRF_VALUE, None) is False
    assert constant_time_equals("", CSRF_VALUE) is False
    assert constant_time_equals(CSRF_VALUE, "") is False
    assert constant_time_equals(CSRF_VALUE, "wrong") is False
    assert constant_time_equals(CSRF_VALUE, CSRF_VALUE) is True


def test_validate_request_origin_accepts_public_and_trusted_origins() -> None:
    """Assert origin validation accepts configured trusted origins."""
    settings = CSRFSettings(
        public_origin="https://public.test",
        trusted_origins=frozenset({"https://trusted.test"}),
    )

    validate_request_origin(
        request=make_request(headers={"origin": "https://trusted.test"}),
        csrf_settings=settings,
    )
    validate_request_origin(
        request=make_request(headers={"referer": "https://public.test/path"}),
        csrf_settings=settings,
    )


@pytest.mark.negative
def test_validate_request_origin_rejects_missing_invalid_and_untrusted_values() -> None:
    """Assert origin validation rejects absent, unparsable, and untrusted origins."""
    settings = CSRFSettings()

    with pytest.raises(CSRFMissingHeaderError):
        validate_request_origin(
            request=make_request(),
            csrf_settings=settings,
        )

    with pytest.raises(CSRFCookieHeaderMismatchError):
        validate_request_origin(
            request=make_request(headers={"origin": "not-a-url"}),
            csrf_settings=settings,
        )

    with pytest.raises(CSRFCookieHeaderMismatchError):
        validate_request_origin(
            request=make_request(headers={"origin": "https://evil.test"}),
            csrf_settings=settings,
        )


def test_validate_request_origin_can_be_disabled() -> None:
    """Assert disabled origin checking accepts requests without origin headers."""
    validate_request_origin(
        request=make_request(),
        csrf_settings=CSRFSettings(origin_check_enabled=False),
    )


def test_validate_double_submit_csrf_accepts_matching_inputs() -> None:
    """Assert double-submit protection accepts matching header and cookie."""
    settings = CSRFSettings()
    validate_double_submit_csrf(
        request=make_request(
            headers={"origin": "https://api.test", settings.header_name: CSRF_VALUE},
            cookies={settings.cookie_name: CSRF_VALUE},
        ),
        csrf_settings=settings,
    )


@pytest.mark.negative
def test_validate_double_submit_csrf_rejects_invalid_inputs() -> None:
    """Assert double-submit protection rejects missing and mismatched tokens."""
    settings = CSRFSettings()

    with pytest.raises(CSRFMissingHeaderError):
        validate_double_submit_csrf(
            request=make_request(headers={"origin": "https://api.test"}),
            csrf_settings=settings,
        )

    with pytest.raises(CSRFMissingCookieError):
        validate_double_submit_csrf(
            request=make_request(
                headers={"origin": "https://api.test", settings.header_name: CSRF_VALUE}
            ),
            csrf_settings=settings,
        )

    with pytest.raises(CSRFCookieHeaderMismatchError):
        validate_double_submit_csrf(
            request=make_request(
                headers={"origin": "https://api.test", settings.header_name: "wrong"},
                cookies={settings.cookie_name: CSRF_VALUE},
            ),
            csrf_settings=settings,
        )
