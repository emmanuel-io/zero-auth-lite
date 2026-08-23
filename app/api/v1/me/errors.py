"""Application errors for current-user account routes."""

from fastapi import status

from app.core.errors.base import AppError


class OAuth2AuthorizationNotFoundError(AppError):
    """Raised when a user does not own the requested OAuth2 authorization."""

    code = "OAUTH2_AUTHORIZATION_NOT_FOUND"
    message = "OAuth2 authorization not found."
    status = status.HTTP_404_NOT_FOUND


class BrowserSessionNotFoundError(AppError):
    """Raised when a user does not own the requested browser session."""

    code = "BROWSER_SESSION_NOT_FOUND"
    message = "Browser session not found."
    status = status.HTTP_404_NOT_FOUND


class CurrentSessionRequiresLogoutError(AppError):
    """Raised when revocation targets the current browser session."""

    code = "CURRENT_SESSION_REQUIRES_LOGOUT"
    message = "The current session must be ended through logout."
    status = status.HTTP_409_CONFLICT
