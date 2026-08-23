"""Datetime normalization at application boundaries."""

from datetime import datetime, UTC


def as_utc_aware(value: datetime) -> datetime:
    """Return a datetime as a timezone-aware UTC value.

    SQLite does not preserve timezone information, even for SQLAlchemy columns
    declared with ``timezone=True``. Naive values read from the canonical
    database therefore represent UTC and are made explicit here.
    """
    if value.tzinfo is None or value.utcoffset() is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)
