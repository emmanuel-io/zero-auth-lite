"""OAuth2 scheme module exceptions."""

from __future__ import annotations

from typing import TYPE_CHECKING

from fastapi import status

from app.core.errors.base import AppError
from app.oauth2.error_codes import OAuth2ErrorCode


if TYPE_CHECKING:
    from collections.abc import Mapping


class OAuth2ProtocolError(Exception):
    """OAuth2 protocol error serialized with RFC-style fields."""

    def __init__(
        self,
        *,
        error: object,
        status_code: int = status.HTTP_400_BAD_REQUEST,
        error_description: str | None = None,
        error_uri: str | None = None,
        headers: Mapping[str, str] | None = None,
    ) -> None:
        """Initialize an OAuth2 protocol error and its HTTP response metadata."""
        super().__init__(error)
        if not isinstance(error, OAuth2ErrorCode):
            msg = "OAuth2 protocol errors require a canonical OAuth2ErrorCode."
            raise TypeError(msg)
        self.error = error
        self.status_code = status_code
        self.error_description = error_description
        self.error_uri = error_uri
        self.headers = dict(headers or {})


class OAuth2AccessTokenInvalidError(AppError):
    """Raised when an OAuth2 access token cannot establish authority."""

    code = "INVALID_ACCESS_TOKEN"
    message = "Invalid access token."
    status = status.HTTP_401_UNAUTHORIZED


class OAuth2TokenSessionInvalidError(AppError):
    """Raised when the persisted OAuth2 session behind a token is invalid."""

    code = "INVALID_ACCESS_TOKEN"
    message = "Invalid access token."
    status = status.HTTP_401_UNAUTHORIZED


class OIDCOpenIDScopeRequiredError(AppError):
    """Raised when UserInfo is called without the required openid scope."""

    code = "OIDC_OPENID_SCOPE_REQUIRED"
    message = "The openid scope is required"
    status = status.HTTP_403_FORBIDDEN


class OAuth2InvalidGrantError(OAuth2ProtocolError):
    """Raised when an OAuth2 grant is invalid."""

    def __init__(self, error_description: str | None = None) -> None:
        """Initialize an invalid_grant protocol error."""
        super().__init__(
            error=OAuth2ErrorCode.INVALID_GRANT,
            status_code=status.HTTP_400_BAD_REQUEST,
            error_description=error_description,
        )


class OAuth2AuthorizationPendingError(OAuth2ProtocolError):
    """Raised while OAuth2 device authorization is still pending."""

    def __init__(self) -> None:
        """Initialize an authorization_pending protocol error."""
        super().__init__(
            error=OAuth2ErrorCode.AUTHORIZATION_PENDING,
            status_code=status.HTTP_400_BAD_REQUEST,
        )


class OAuth2SlowDownError(OAuth2ProtocolError):
    """Raised when an OAuth2 device client polls too quickly."""

    def __init__(self) -> None:
        """Initialize a slow_down protocol error."""
        super().__init__(
            error=OAuth2ErrorCode.SLOW_DOWN,
            status_code=status.HTTP_400_BAD_REQUEST,
        )


class InvalidClientError(OAuth2ProtocolError):
    """Raised when OAuth2 client authentication fails."""

    def __init__(self, *, challenge_basic: bool = False) -> None:
        """Initialize an invalid_client protocol error."""
        super().__init__(
            error=OAuth2ErrorCode.INVALID_CLIENT,
            status_code=status.HTTP_401_UNAUTHORIZED,
            headers={"WWW-Authenticate": 'Basic realm="oauth2/token"'}
            if challenge_basic
            else None,
        )
