"""Tests for shared UTC datetime helpers."""

from datetime import datetime, timedelta, timezone, UTC

import pytest
from app.core.time import as_utc_aware


pytestmark = pytest.mark.unit


def test_as_utc_aware_converts_aware_datetime() -> None:
    """Assert aware values are normalized to UTC."""
    value = datetime(2026, 5, 6, 16, 0, tzinfo=timezone(timedelta(hours=4)))

    assert as_utc_aware(value) == datetime(2026, 5, 6, 12, 0, tzinfo=UTC)


def test_as_utc_aware_treats_naive_database_datetime_as_utc() -> None:
    """Assert naive SQLite values are interpreted as UTC."""
    value = datetime(2026, 5, 6, 12, 0)  # noqa: DTZ001

    assert as_utc_aware(value) == datetime(2026, 5, 6, 12, 0, tzinfo=UTC)
