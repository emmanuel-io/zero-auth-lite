"""Client-safe errors for SQLite persistence failures."""

from typing import ClassVar

from fastapi import status

from app.core.errors.base import AppError
from app.errors import DataConflictError


class DatabaseBusyError(AppError):
    """Raised when SQLite cannot acquire its single-writer lock in time."""

    code = "DATABASE_BUSY"
    message = "The database is temporarily busy. Retry the request."
    status = status.HTTP_503_SERVICE_UNAVAILABLE
    headers: ClassVar[dict[str, str]] = {"Retry-After": "1"}


class ConstraintViolationError(DataConflictError):
    """Raised on constraint violations."""

    code = "DATA_CONFLICT"
    message = "The requested data conflicts with stored data."
    status = status.HTTP_409_CONFLICT
    redact_details_in_deployment = True


class UniqueViolationError(ConstraintViolationError):
    """Raised when a unique constraint is violated."""

    example_key = "DATA_CONFLICT_UNIQUE"
    detail_type = "unique_violation"
    detail_message = "A value that must be unique is already in use."


class CheckViolationError(ConstraintViolationError):
    """Raised when a check constraint is violated."""

    example_key = "DATA_CONFLICT_CHECK"
    detail_type = "check_violation"
    detail_message = "A stored-data rule rejected the requested value."


class ForeignKeyViolationError(ConstraintViolationError):
    """Raised when a foreign key constraint is violated."""

    example_key = "DATA_CONFLICT_FOREIGN_KEY"
    detail_type = "foreign_key_violation"
    detail_message = "A referenced object does not exist or is still in use."


class NotNullViolationError(ConstraintViolationError):
    """Raised when a not-null constraint is violated."""

    example_key = "DATA_CONFLICT_NOT_NULL"
    detail_type = "not_null_violation"
    detail_message = "A required stored value is missing."
