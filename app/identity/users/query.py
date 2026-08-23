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


def clean_query(value: str | None) -> str | None:
    """Return stripped query text or ``None`` for empty input.

    Args:
        value: Raw query parameter value.

    Returns:
        Normalized query text, or ``None`` when the input is empty.
    """
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
    """Parse a public sort parameter into SQLAlchemy order expressions.

    Args:
        sort: Public sort key, optionally prefixed with ``-`` for descending.
        allowed: Mapping of public sort keys to SQLAlchemy expressions.
        default: Expressions to use when no sort key is supplied.

    Returns:
        A list of SQLAlchemy order expressions.

    Raises:
        ValueError: If the sort key is not allow-listed.
    """
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
    """Build a case-insensitive SQL search predicate.

    Args:
        q: Search text.
        columns: Columns or SQL expressions to search.

    Returns:
        SQLAlchemy predicate, or ``None`` when no search text is provided.
    """
    cleaned = clean_query(q)
    if cleaned is None:
        return None
    pattern = f"%{cleaned}%"
    return or_(*(column.ilike(pattern) for column in columns))


def created_window_filter(
    *,
    column: Any,  # noqa: ANN401
    created_from: date | None,
    created_to: date | None,
) -> ColumnElement[bool] | None:
    """Build an inclusive date-window filter for timestamp columns.

    Args:
        column: Timestamp column to filter.
        created_from: Inclusive lower date bound.
        created_to: Inclusive upper date bound.

    Returns:
        SQLAlchemy predicate, or ``None`` when no bounds are provided.
    """
    conditions: list[ColumnElement[bool]] = []
    if created_from is not None:
        start = datetime.combine(created_from, time.min, tzinfo=UTC)
        conditions.append(column >= start)
    if created_to is not None:
        end = datetime.combine(created_to + timedelta(days=1), time.min, tzinfo=UTC)
        conditions.append(column < end)
    if not conditions:
        return None
    return and_(*conditions)


def compact_filters(
    *filters: ColumnElement[bool] | None,
) -> list[ColumnElement[bool]]:
    """Return non-empty SQLAlchemy filters.

    Args:
        *filters: Optional filter expressions.

    Returns:
        List of concrete SQLAlchemy filter expressions.
    """
    return [condition for condition in filters if condition is not None]


def boolean_state_filter(
    column: InstrumentedAttribute[bool], *, value: bool | None
) -> ColumnElement[bool] | None:
    """Build a boolean SQL predicate only when a filter value is present."""
    return None if value is None else column.is_(value)


def named_boolean_filter(
    column: InstrumentedAttribute[bool],
    *,
    value: str | None,
    true_name: str,
    false_name: str,
) -> ColumnElement[bool] | None:
    """Map two public names to a boolean SQL predicate."""
    if value == true_name:
        return column.is_(True)
    if value == false_name:
        return column.is_(False)
    return None
