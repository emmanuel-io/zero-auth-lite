"""OAuth2 grant vocabularies used by protocol requests and stored sessions."""

from enum import StrEnum


class OAuth2GrantType(StrEnum):
    """Grant types accepted by the OAuth2 token endpoint."""

    AUTHORIZATION_CODE = "authorization_code"
    REFRESH_TOKEN = "refresh_token"  # noqa: S105
    CLIENT_CREDENTIALS = "client_credentials"
    DEVICE_CODE = "urn:ietf:params:oauth:grant-type:device_code"


class OAuth2SessionGrantType(StrEnum):
    """Grant types that can originate a persisted OAuth2 session."""

    AUTHORIZATION_CODE = "authorization_code"
    CLIENT_CREDENTIALS = "client_credentials"
    DEVICE_CODE = "urn:ietf:params:oauth:grant-type:device_code"
