"""Tests for reusable identity administration query helpers."""

from datetime import date

import pytest
from app.identity.users.query import (
    clean_query,
    compact_filters,
    created_window_filter,
    parse_sort,
    search_filter,
)
from sqlalchemy import column


pytestmark = pytest.mark.unit


def test_list_sort_parser_uses_allow_list_and_descending_prefix() -> None:
    """Assert list sort parsing maps public keys to explicit expressions."""
    created_at = column("created_at")

    parsed = parse_sort(
        sort="-created_at",
        allowed={"created_at": created_at},
        default=[created_at.asc()],
    )

    assert "created_at DESC" in str(parsed[0])


def test_list_sort_parser_rejects_unknown_public_key() -> None:
    """Assert list sort parsing rejects fields outside the allow-list."""
    with pytest.raises(ValueError, match="Invalid sort key"):
        parse_sort(
            sort="raw_sql",
            allowed={"created_at": column("created_at")},
            default=[],
        )


def test_list_query_helpers_ignore_empty_inputs() -> None:
    """Assert empty query values do not produce filters."""
    email_filter = column("email") == "a"

    assert clean_query("   ") is None
    assert search_filter(q="", columns=[column("email")]) is None
    assert compact_filters(None, email_filter) == [email_filter]


def test_created_window_filter_builds_inclusive_date_bounds() -> None:
    """Assert date window filters include the full upper-bound day."""
    expression = created_window_filter(
        column=column("created_at"),
        created_from=date(2026, 5, 1),
        created_to=date(2026, 5, 19),
    )

    rendered = str(expression)

    assert "created_at >=" in rendered
    assert "created_at <" in rendered
