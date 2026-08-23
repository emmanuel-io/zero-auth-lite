"""Issuer-derived public URL helpers for OAuth2 and OpenID Connect."""

from urllib.parse import urlsplit, urlunsplit

from fastapi import Request


def authorization_server_metadata_path(issuer: str) -> str:
    """Derive the RFC 8414 authorization-server metadata path."""
    issuer_path = urlsplit(issuer).path.rstrip("/")
    if not issuer_path:
        return "/.well-known/oauth-authorization-server"
    return f"/.well-known/oauth-authorization-server{issuer_path}"


def openid_configuration_path(issuer: str) -> str:
    """Derive the OpenID Connect discovery path."""
    issuer_path = urlsplit(issuer).path.rstrip("/")
    return f"{issuer_path}/.well-known/openid-configuration"


def public_route_url(request: Request, *, issuer: str, route_name: str) -> str:
    """Return a named application route on the configured issuer origin."""
    route = urlsplit(str(request.url_for(route_name)))
    configured_issuer = urlsplit(issuer)
    return urlunsplit(
        (
            configured_issuer.scheme,
            configured_issuer.netloc,
            route.path,
            route.query,
            "",
        )
    )


def public_path_url(*, issuer: str, path: str) -> str:
    """Return a fixed public path on the configured issuer origin."""
    configured_issuer = urlsplit(issuer)
    issuer_path = configured_issuer.path.rstrip("/")
    return urlunsplit(
        (
            configured_issuer.scheme,
            configured_issuer.netloc,
            f"{issuer_path}/{path.lstrip('/')}",
            "",
            "",
        )
    )
