"""Shared SQL query helpers for identity administration searches.

The helpers keep validated search criteria separate from SQLAlchemy columns and
return expressions that the owning identity services can apply explicitly.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from datetime import date, datetime, time, timedelta, UTC
from typing import Any, TYPE_CHECKING

from sqlalchemy import and_, or_


if TYPE_CHECKING:
    from sqlalchemy.orm import InstrumentedAttribute
    from sqlalchemy.sql import ColumnElement


type SortExpression = Any
type SortValue = SortExpression | Sequence[SortExpression]
LIKE_ESCAPE = "\\"


def clean_query(value: str | None) -> str | None:
    """Return stripped query text or ``None`` for empty input."""
    if value is None:
        return None
    cleaned = value.strip()
    return cleaned or None


def parse_sort(
    *,
    sort: str | None,
    allowed: Mapping[str, SortValue],
    default: Sequence[SortExpression],
) -> list[SortExpression]:
    """Parse an allow-listed sort key, using a leading ``-`` for descending."""
    key = clean_query(sort)
    if key is None:
        return list(default)

    descending = key.startswith("-")
    public_key = key[1:] if descending else key
    if public_key not in allowed:
        msg = f"Invalid sort key: {public_key!r}"
        raise ValueError(msg)

    value = allowed[public_key]
    expressions = list(value) if isinstance(value, Sequence) else [value]
    if descending:
        return [expression.desc() for expression in expressions]
    return [expression.asc() for expression in expressions]


def search_filter(
    *,
    q: str | None,
    columns: Sequence[Any],
) -> ColumnElement[bool] | None:
    """Build a case-insensitive literal-substring predicate across columns."""
    cleaned = clean_query(q)
    if cleaned is None:
        return None
    literal = (
        cleaned.replace(LIKE_ESCAPE, LIKE_ESCAPE * 2)
        .replace("%", f"{LIKE_ESCAPE}%")
        .replace("_", f"{LIKE_ESCAPE}_")
    )
    pattern = f"%{literal}%"
    return or_(*(column.ilike(pattern, escape=LIKE_ESCAPE) for column in columns))


def created_window_filter(
    *,
    column: Any,  # noqa: ANN401
    created_from: date | None,
    created_to: date | None,
) -> ColumnElement[bool] | None:
    """Build a UTC timestamp predicate from inclusive calendar-date bounds."""
    conditions: list[ColumnElement[bool]] = []
    if created_from is not None:
        start = datetime.combine(created_from, time.min, tzinfo=UTC)
        conditions.append(column >= start)
    if created_to is not None and created_to < date.max:
        end = datetime.combine(created_to + timedelta(days=1), time.min, tzinfo=UTC)
        conditions.append(column < end)
    if not conditions:
        return None
    return and_(*conditions)


def compact_filters(
    *filters: ColumnElement[bool] | None,
) -> list[ColumnElement[bool]]:
    """Return the concrete expressions from a sequence of optional filters."""
    return [condition for condition in filters if condition is not None]


def boolean_state_filter(
    column: InstrumentedAttribute[bool], *, value: bool | None
) -> ColumnElement[bool] | None:
    """Build a boolean SQL predicate only when a filter value is present."""
    return None if value is None else column.is_(value)
