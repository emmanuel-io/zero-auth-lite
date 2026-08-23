"""Exceptions for single-use authentication tokens."""

from fastapi import status

from app.core.errors.base import AppError


class InvalidAuthTokenError(AppError):
    """Raised when an auth workflow token is unknown, expired, or already used."""

    code = "INVALID_AUTH_TOKEN"
    message = "Authentication token is invalid or expired."
    status = status.HTTP_400_BAD_REQUEST


class AuthTokenDerivationKeyError(RuntimeError):
    """Raised when a persisted event token cannot be reproduced safely."""
