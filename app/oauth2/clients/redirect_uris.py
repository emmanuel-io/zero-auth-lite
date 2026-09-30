"""Validation rules for registered OAuth2 redirect URIs."""

from pydantic import HttpUrl, TypeAdapter, ValidationError

from app.oauth2.clients.management.errors import OAuth2ClientManagementErrorReason


LOOPBACK_REDIRECT_HOSTS = frozenset({"localhost", "127.0.0.1", "::1"})
_HTTP_URL_ADAPTER = TypeAdapter(HttpUrl)


def validate_redirect_uri(redirect_uri: str | HttpUrl) -> None:
    """Require HTTPS, except for HTTP loopback development callbacks."""
    try:
        parsed_uri = _HTTP_URL_ADAPTER.validate_python(redirect_uri)
    except ValidationError as exc:
        raise ValueError(
            OAuth2ClientManagementErrorReason.REDIRECT_URI_INVALID
        ) from exc
    if parsed_uri.fragment:
        raise ValueError(
            OAuth2ClientManagementErrorReason.REDIRECT_URI_FRAGMENT_NOT_ALLOWED
        )
    if parsed_uri.scheme == "https":
        return
    if parsed_uri.scheme == "http" and parsed_uri.host in LOOPBACK_REDIRECT_HOSTS:
        return
    raise ValueError(OAuth2ClientManagementErrorReason.REDIRECT_URI_HTTPS_REQUIRED)


def validate_redirect_uris[T: (str, HttpUrl)](redirect_uris: list[T]) -> list[T]:
    """Validate and preserve a list of registered redirect URIs."""
    normalized = [str(redirect_uri) for redirect_uri in redirect_uris]
    if len(normalized) != len(set(normalized)):
        raise ValueError(OAuth2ClientManagementErrorReason.DUPLICATE_VALUES_NOT_ALLOWED)
    for redirect_uri in redirect_uris:
        validate_redirect_uri(redirect_uri)
    return redirect_uris
