"""Tests for trusted-proxy source IP resolution."""

import pytest
from app.core.request_ip import (
    _clean_forwarded_ip,
    _is_trusted_proxy,
    get_source_ip,
)
from app.settings.app import AppSettings
from app.settings.root import Settings
from app.settings.state import set_settings_snapshot
from fastapi import FastAPI
from starlette.requests import Request


pytestmark = pytest.mark.unit


def build_request(
    *,
    direct_peer: str,
    trusted_proxy_ips: list[str] | None = None,
    headers: dict[str, str] | None = None,
) -> Request:
    """Build a Starlette request with app settings for IP resolution.

    Args:
        direct_peer: Direct socket peer IP.
        trusted_proxy_ips: Configured trusted proxy IPs or CIDR ranges.
        headers: Request headers to include.

    Returns:
        Request: Request object suitable for source IP extraction.
    """
    app = FastAPI()
    set_settings_snapshot(
        app,
        Settings(
            app=AppSettings(trusted_proxy_ips=tuple(trusted_proxy_ips or [])),
        ),
    )
    raw_headers = [
        (key.lower().encode(), value.encode()) for key, value in (headers or {}).items()
    ]
    return Request(
        {
            "type": "http",
            "method": "GET",
            "path": "/",
            "headers": raw_headers,
            "client": (direct_peer, 12345),
            "app": app,
        }
    )


def test_get_source_ip_uses_direct_peer_without_trusted_proxy() -> None:
    """Assert forwarded headers are ignored when no trusted proxy is configured."""
    request = build_request(
        direct_peer="203.0.113.20",
        headers={"x-forwarded-for": "198.51.100.10"},
    )

    assert get_source_ip(request) == "203.0.113.20"


def test_get_source_ip_ignores_spoofed_header_from_untrusted_peer() -> None:
    """Assert untrusted peers cannot spoof source IP with forwarded headers."""
    request = build_request(
        direct_peer="203.0.113.20",
        trusted_proxy_ips=["127.0.0.1"],
        headers={"x-forwarded-for": "198.51.100.10"},
    )

    assert get_source_ip(request) == "203.0.113.20"


def test_get_source_ip_uses_x_forwarded_for_from_trusted_proxy() -> None:
    """Assert a trusted proxy can supply the original client IP."""
    request = build_request(
        direct_peer="127.0.0.1",
        trusted_proxy_ips=["127.0.0.1"],
        headers={"x-forwarded-for": "198.51.100.10"},
    )

    assert get_source_ip(request) == "198.51.100.10"


def test_get_source_ip_resolves_multi_hop_forwarded_chain() -> None:
    """Assert trusted proxy hops are skipped from right to left."""
    request = build_request(
        direct_peer="10.0.0.2",
        trusted_proxy_ips=["10.0.0.0/8"],
        headers={"x-forwarded-for": "198.51.100.10, 10.0.0.3"},
    )

    assert get_source_ip(request) == "198.51.100.10"


def test_get_source_ip_uses_forwarded_header_when_xff_missing() -> None:
    """Assert RFC Forwarded headers are used when X-Forwarded-For is absent."""
    request = build_request(
        direct_peer="127.0.0.1",
        trusted_proxy_ips=["127.0.0.1"],
        headers={"forwarded": 'for="198.51.100.10";proto=https'},
    )

    assert get_source_ip(request) == "198.51.100.10"


def test_get_source_ip_falls_back_to_direct_peer_for_malformed_headers() -> None:
    """Assert malformed forwarded headers do not override the direct peer."""
    request = build_request(
        direct_peer="127.0.0.1",
        trusted_proxy_ips=["127.0.0.1"],
        headers={"x-forwarded-for": "not-an-ip"},
    )

    assert get_source_ip(request) == "127.0.0.1"


def test_clean_forwarded_ip_handles_empty_ipv6_and_host_port_values() -> None:
    """Assert forwarded IP cleanup handles common header forms."""
    assert _clean_forwarded_ip("") is None
    assert _clean_forwarded_ip("[2001:db8::1]:443") == "2001:db8::1"
    assert _clean_forwarded_ip("198.51.100.10:1234") == "198.51.100.10"


def test_invalid_trusted_proxy_values_are_ignored() -> None:
    """Assert invalid peer and CIDR values are treated as untrusted."""
    assert (
        _is_trusted_proxy(
            peer="not-an-ip",
            trusted_proxy_ips=["127.0.0.1"],
        )
        is False
    )
    assert (
        _is_trusted_proxy(
            peer="127.0.0.1",
            trusted_proxy_ips=["not-a-cidr"],
        )
        is False
    )


def test_get_source_ip_returns_first_hop_when_all_forwarded_hops_are_trusted() -> None:
    """Assert all-trusted chains fall back to the original forwarded hop."""
    request = build_request(
        direct_peer="10.0.0.2",
        trusted_proxy_ips=["10.0.0.0/8"],
        headers={"x-forwarded-for": "10.0.0.1, 10.0.0.3"},
    )

    assert get_source_ip(request) == "10.0.0.1"


def test_get_source_ip_returns_unknown_without_client_peer() -> None:
    """Assert requests without socket peer use the stable unknown marker."""
    request = build_request(direct_peer="127.0.0.1")
    request.scope["client"] = None

    assert get_source_ip(request) == "unknown"
