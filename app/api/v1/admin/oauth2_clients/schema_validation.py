"""Shared validation primitives for OAuth2 client HTTP schemas."""

from typing import Annotated

from pydantic import Field, HttpUrl

from app.identity.public_ids import ORGANIZATION_ID_PATTERN
from app.oauth2.specs import OAuth2Specs


RedirectUri = Annotated[HttpUrl, Field(max_length=OAuth2Specs.REDIRECT_URI_LENGTH_MAX)]
OrganizationPublicId = Annotated[str, Field(pattern=ORGANIZATION_ID_PATTERN)]
LOOPBACK_REDIRECT_HOSTS = frozenset({"localhost", "127.0.0.1", "::1"})
ERR_REDIRECT_URI_FRAGMENT = "redirect_uri_fragment_not_allowed"
ERR_REDIRECT_URI_HTTPS = "redirect_uri_https_required"


def validate_redirect_uri(redirect_uri: HttpUrl) -> HttpUrl:
    """Validate one registered OAuth2 redirect URI."""
    if redirect_uri.fragment:
        raise ValueError(ERR_REDIRECT_URI_FRAGMENT)
    if redirect_uri.scheme == "https":
        return redirect_uri
    if redirect_uri.scheme == "http" and redirect_uri.host in LOOPBACK_REDIRECT_HOSTS:
        return redirect_uri
    raise ValueError(ERR_REDIRECT_URI_HTTPS)


def validate_redirect_uris(redirect_uris: list[HttpUrl]) -> list[HttpUrl]:
    """Validate registered OAuth2 redirect URIs."""
    return [validate_redirect_uri(redirect_uri) for redirect_uri in redirect_uris]


def reject_duplicates[T](values: list[T]) -> list[T]:
    """Reject repeated client configuration values."""
    normalized = [str(value) for value in values]
    if len(normalized) != len(set(normalized)):
        msg = "duplicate_values_not_allowed"
        raise ValueError(msg)
    return values
