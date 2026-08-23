"""Validation helpers for API date-range query parameters."""

from datetime import date

from app.api.errors import StartDateAfterEndDateError


def validate_date_range(*, start: date | None, end: date | None) -> None:
    """Reject a date range whose inclusive lower bound follows its upper bound."""
    if start is not None and end is not None and start > end:
        raise StartDateAfterEndDateError
