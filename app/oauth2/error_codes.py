"""Public OAuth2 error codes and internal validation reasons."""

from enum import StrEnum


class OAuth2ErrorCode(StrEnum):
    """Error identifiers serialized by OAuth2 and OpenID Connect endpoints."""

    INVALID_REQUEST = "invalid_request"
    INVALID_CLIENT = "invalid_client"
    INVALID_GRANT = "invalid_grant"
    UNAUTHORIZED_CLIENT = "unauthorized_client"
    UNSUPPORTED_GRANT_TYPE = "unsupported_grant_type"
    INVALID_SCOPE = "invalid_scope"
    ACCESS_DENIED = "access_denied"
    AUTHORIZATION_PENDING = "authorization_pending"
    SLOW_DOWN = "slow_down"
    EXPIRED_TOKEN = "expired_token"  # noqa: S105
    UNSUPPORTED_TOKEN_TYPE = "unsupported_token_type"  # noqa: S105
    UNSUPPORTED_RESPONSE_TYPE = "unsupported_response_type"
    SERVER_ERROR = "server_error"
    TEMPORARILY_UNAVAILABLE = "temporarily_unavailable"
    INVALID_TOKEN = "invalid_token"  # noqa: S105
    INSUFFICIENT_SCOPE = "insufficient_scope"


class OAuth2ValidationReason(StrEnum):
    """Internal validation reasons that are not public OAuth2 error codes."""

    INVALID_REDIRECT_URI = "invalid_redirect_uri"
