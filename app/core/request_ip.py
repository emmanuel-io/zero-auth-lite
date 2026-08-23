"""Source IP extraction for security-relevant session metadata."""

from ipaddress import ip_address, ip_network
from logging import getLogger

from fastapi import Request

from app.settings.state import get_settings_snapshot


logger = getLogger(__name__)


def _configured_trusted_proxies(request: Request) -> list[str]:
    """Return trusted proxy CIDRs configured on application settings."""
    return list(get_settings_snapshot(request.app).app.trusted_proxy_ips)


def _is_trusted_proxy(*, peer: str, trusted_proxy_ips: list[str]) -> bool:
    """Return whether a peer IP is trusted to supply forwarded headers."""
    if not trusted_proxy_ips:
        return False
    try:
        peer_ip = ip_address(peer)
    except ValueError:
        return False
    for item in trusted_proxy_ips:
        try:
            if peer_ip in ip_network(item, strict=False):
                return True
        except ValueError:
            logger.warning("Ignoring invalid trusted proxy entry: %s", item)
    return False


def _is_trusted_forwarded_hop(*, hop: str, trusted_proxy_ips: list[str]) -> bool:
    """Return whether a forwarded-hop IP is configured as trusted."""
    return _is_trusted_proxy(peer=hop, trusted_proxy_ips=trusted_proxy_ips)


def _clean_forwarded_ip(value: str) -> str | None:
    """Normalize one forwarded IP value."""
    candidate = value.strip().strip('"')
    if not candidate:
        return None
    if candidate.startswith("[") and "]" in candidate:
        candidate = candidate[1 : candidate.index("]")]
    elif candidate.count(":") == 1 and "." in candidate:
        candidate = candidate.rsplit(":", 1)[0]
    try:
        return str(ip_address(candidate))
    except ValueError:
        return None


def _parse_x_forwarded_for(header_value: str | None) -> list[str]:
    """Parse an X-Forwarded-For header into valid IP hops."""
    if not header_value:
        return []
    hops: list[str] = []
    for item in header_value.split(","):
        cleaned = _clean_forwarded_ip(item)
        if cleaned is not None:
            hops.append(cleaned)
    return hops


def _parse_forwarded(header_value: str | None) -> list[str]:
    """Parse a Forwarded header into valid IP hops."""
    if not header_value:
        return []
    hops: list[str] = []
    for forwarded_element in header_value.split(","):
        for parameter in forwarded_element.split(";"):
            key, separator, value = parameter.strip().partition("=")
            if separator and key.lower() == "for":
                cleaned = _clean_forwarded_ip(value)
                if cleaned is not None:
                    hops.append(cleaned)
    return hops


def _client_from_forwarded_chain(
    *,
    forwarded_hops: list[str],
    direct_peer: str,
    trusted_proxy_ips: list[str],
) -> str | None:
    """Return the first untrusted client IP from a forwarded chain."""
    if not forwarded_hops:
        return None
    chain = [*forwarded_hops, direct_peer]
    for hop in reversed(chain):
        if not _is_trusted_forwarded_hop(
            hop=hop,
            trusted_proxy_ips=trusted_proxy_ips,
        ):
            return hop
    return forwarded_hops[0]


def get_source_ip(request: Request) -> str:
    """Return the resolved client IP for session metadata."""
    if request.client is None:
        return "unknown"
    direct_peer = request.client.host
    trusted_proxy_ips = _configured_trusted_proxies(request)
    if not _is_trusted_proxy(peer=direct_peer, trusted_proxy_ips=trusted_proxy_ips):
        return direct_peer

    forwarded_hops = _parse_x_forwarded_for(request.headers.get("x-forwarded-for"))
    if not forwarded_hops:
        forwarded_hops = _parse_forwarded(request.headers.get("forwarded"))
    return (
        _client_from_forwarded_chain(
            forwarded_hops=forwarded_hops,
            direct_peer=direct_peer,
            trusted_proxy_ips=trusted_proxy_ips,
        )
        or direct_peer
    )
