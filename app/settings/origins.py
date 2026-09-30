"""Validation helpers for public HTTP origins."""

import re
from ipaddress import ip_address
from urllib.parse import urlsplit

from pydantic import AnyHttpUrl


_DNS_LABEL = r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
COOKIE_DOMAIN_PATTERN = re.compile(rf"^(?=.{{1,253}}$){_DNS_LABEL}(?:\.{_DNS_LABEL})*$")


def is_local_hostname(hostname: str | None) -> bool:
    """Return whether a hostname belongs to a local-only topology."""
    if hostname is None:
        return False
    normalized = hostname.rstrip(".").casefold()
    if normalized == "localhost" or normalized.endswith(".localhost"):
        return True
    try:
        return ip_address(normalized).is_loopback
    except ValueError:
        return False


def hostname_matches_trusted_host(hostname: str, trusted_host: str) -> bool:
    """Return whether one hostname is accepted by a TrustedHost pattern."""
    normalized_hostname = hostname.rstrip(".").casefold()
    normalized_pattern = trusted_host.rstrip(".").casefold()
    if normalized_pattern.startswith("*."):
        return normalized_hostname.endswith(normalized_pattern[1:])
    return normalized_hostname == normalized_pattern


def validate_cookie_domain(*, name: str, value: str) -> str:
    """Return a canonical DNS cookie domain or reject an invalid value."""
    normalized = value.removeprefix(".").rstrip(".").casefold()
    if value != value.strip() or not COOKIE_DOMAIN_PATTERN.fullmatch(normalized):
        msg = f"{name} must be a valid DNS cookie domain"
        raise ValueError(msg)
    return normalized


def cookie_domain_matches_hostname(*, domain: str, hostname: str) -> bool:
    """Return whether a Domain cookie can be scoped to one request hostname."""
    normalized_domain = domain.removeprefix(".").rstrip(".").casefold()
    normalized_hostname = hostname.rstrip(".").casefold()
    return normalized_hostname == normalized_domain or normalized_hostname.endswith(
        f".{normalized_domain}"
    )


def normalize_http_origin(*, name: str, value: str) -> str:
    """Validate and return one canonical HTTP(S) origin."""
    try:
        normalized_url = str(AnyHttpUrl(value))
    except ValueError as exc:
        msg = f"{name} must be a valid absolute HTTP(S) origin"
        raise ValueError(msg) from exc
    parsed = urlsplit(normalized_url)
    if (
        parsed.username is not None
        or parsed.password is not None
        or parsed.path not in {"", "/"}
        or parsed.query
        or parsed.fragment
    ):
        msg = f"{name} must be a valid absolute HTTP(S) origin"
        raise ValueError(msg)
    return f"{parsed.scheme}://{parsed.netloc}"


def validate_absolute_http_origin(*, name: str, value: str) -> None:
    """Require an exact HTTP(S) origin without credentials or URL components."""
    normalize_http_origin(name=name, value=value)


def require_deployment_https_url(
    *, name: str, value: str, description: str | None = None
) -> None:
    """Require HTTPS and a non-local host for a public deployment URL."""
    if urlsplit(value).scheme != "https":
        msg = (
            f"Deployment mode requires an HTTPS {description}"
            if description is not None
            else f"Deployment mode requires HTTPS in {name}"
        )
        raise ValueError(msg)
    if is_local_hostname(urlsplit(value).hostname):
        msg = f"Deployment mode rejects local-only host in {name}"
        raise ValueError(msg)


def validate_deployment_http_origin(
    *, name: str, value: str, description: str | None = None
) -> None:
    """Require one exact, non-local HTTPS origin for deployment."""
    validate_absolute_http_origin(name=name, value=value)
    require_deployment_https_url(
        name=name,
        value=value,
        description=description,
    )
