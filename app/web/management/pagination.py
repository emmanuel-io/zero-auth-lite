"""Pagination links shared by management browser lists."""

from collections.abc import Mapping
from dataclasses import dataclass
from urllib.parse import urlencode


@dataclass(frozen=True, slots=True)
class PaginationLinks:
    """Previous and next links for one page of management results."""

    previous_url: str | None
    next_url: str | None


def page_url(path: str, *, offset: int, limit: int, **filters: object) -> str:
    """Build a stable pagination link while preserving active filters."""
    values = {key: value for key, value in filters.items() if value is not None}
    values.update(offset=max(offset, 0), limit=limit)
    return f"{path}?{urlencode(values)}"


def pagination_links(
    path: str,
    *,
    filters: Mapping[str, object],
    offset: int,
    limit: int,
    total: int,
) -> PaginationLinks:
    """Build bounded previous and next links while preserving list filters."""
    return PaginationLinks(
        previous_url=(
            page_url(path, offset=offset - limit, limit=limit, **filters)
            if offset > 0
            else None
        ),
        next_url=(
            page_url(path, offset=offset + limit, limit=limit, **filters)
            if offset + limit < total
            else None
        ),
    )
