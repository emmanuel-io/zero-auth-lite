"""Identity-domain errors shared by user-management services."""

from fastapi import status

from app.core.errors.base import AppError


class CurrentPasswordMismatchError(AppError):
    """Report that the supplied current password does not match the account."""

    code = "INVALID_PASSWORD"
    message = "Invalid password"
    status = status.HTTP_401_UNAUTHORIZED
