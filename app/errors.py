"""Application errors serialized by the server error handler."""

from typing import ClassVar

from fastapi import status

from app.core.errors.base import AppError


class ObjectNotFoundError(AppError):
    """Raised when an object is not found."""

    code = "NOT_FOUND"
    message = "The requested object was not found."
    status = status.HTTP_404_NOT_FOUND


class ObjectAlreadyExistsError(AppError):
    """Raised when an object already exists."""

    code = "ALREADY_EXISTS"
    message = "The object already exists."
    status = status.HTTP_409_CONFLICT


class ForbiddenOperationError(AppError):
    """Raised when the current principal cannot perform an operation."""

    code = "FORBIDDEN_OPERATION"
    message = "Operation forbidden for the current principal."
    status = status.HTTP_403_FORBIDDEN


class DataConflictError(AppError):
    """Raised when data cannot be changed because of a conflict."""

    code = "DATA_CONFLICT"
    message = "Data conflict error."
    status = status.HTTP_409_CONFLICT


class UnauthorizedError(AppError):
    """Raised when authentication is missing or invalid."""

    code = "UNAUTHORIZED"
    message = "Unauthorized operation."
    status = status.HTTP_401_UNAUTHORIZED
    headers: ClassVar[dict[str, str]] = {"WWW-Authenticate": "Bearer"}
