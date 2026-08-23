"""Application API exceptions."""

from fastapi import status

from app.core.errors.base import AppError


class StartDateAfterEndDateError(AppError):
    """Raised when a date range starts after it ends."""

    code = "START_DATE_AFTER_END_DATE"
    message = "Start date is after end date"
    status = status.HTTP_400_BAD_REQUEST


class InvalidPublicIdError(AppError):
    """Raised when a public identifier is invalid."""

    code = "INVALID_PUBLIC_ID"
    message = "Invalid public ID"
    status = status.HTTP_400_BAD_REQUEST
