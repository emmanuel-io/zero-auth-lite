"""OAuth2 scheme module exceptions."""

from __future__ import annotations

from typing import TYPE_CHECKING

from fastapi import status

from app.core.errors.base import AppError


if TYPE_CHECKING:
    from collections.abc import Mapping


class OAuth2ProtocolError(Exception):
    """OAuth2 protocol error serialized with RFC-style fields."""

    def __init__(
        self,
        *,
        error: str,
        status_code: int = status.HTTP_400_BAD_REQUEST,
        error_description: str | None = None,
        error_uri: str | None = None,
        headers: Mapping[str, str] | None = None,
    ) -> None:
        """Initialize the OAuth2 protocol error.

        Args:
            error: Stable OAuth2 error code.
            status_code: HTTP status code for the response.
            error_description: Optional human-readable diagnostic.
            error_uri: Optional URI pointing to human-readable documentation.
            headers: Optional response headers.
        """
        super().__init__(error)
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


class OAuth2SessionInvalidError(AppError):
    """Raised when the authorization session behind a token is invalid."""

    code = "INVALID_ACCESS_TOKEN"
    message = "Invalid access token."
    status = status.HTTP_401_UNAUTHORIZED


class OIDCOpenIDScopeRequiredError(AppError):
    """Raised when UserInfo is called without the required openid scope."""

    code = "OIDC_OPENID_SCOPE_REQUIRED"
    message = "The openid scope is required"
    status = status.HTTP_403_FORBIDDEN


class OAuth2InvalidGrantError(OAuth2ProtocolError):
    """Handle OAuth2 invalid_grant errors."""

    def __init__(self, error_description: str | None = None) -> None:
        """Initialize an invalid_grant protocol error."""
        super().__init__(
            error="invalid_grant",
            status_code=status.HTTP_400_BAD_REQUEST,
            error_description=error_description,
        )


class OAuth2AuthorizationPendingError(OAuth2ProtocolError):
    """Handle OAuth2 authorization_pending errors."""

    def __init__(self) -> None:
        """Initialize an authorization_pending protocol error."""
        super().__init__(
            error="authorization_pending",
            status_code=status.HTTP_400_BAD_REQUEST,
        )


class OAuth2SlowDownError(OAuth2ProtocolError):
    """Handle OAuth2 slow_down errors."""

    def __init__(self) -> None:
        """Initialize a slow_down protocol error."""
        super().__init__(
            error="slow_down",
            status_code=status.HTTP_400_BAD_REQUEST,
        )


class InvalidClientError(OAuth2ProtocolError):
    """Handles invalid client authentication errors."""

    def __init__(self, *, challenge_basic: bool = False) -> None:
        """Initialize an invalid_client protocol error."""
        super().__init__(
            error="invalid_client",
            status_code=status.HTTP_401_UNAUTHORIZED,
            headers={"WWW-Authenticate": 'Basic realm="oauth2/token"'}
            if challenge_basic
            else None,
        )
