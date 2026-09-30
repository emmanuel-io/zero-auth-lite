"""Tests for management pagination links."""

from urllib.parse import parse_qs, urlsplit

from app.web.management.pagination import pagination_links


def test_pagination_links_preserve_filters_between_pages() -> None:
    """Keep active filters in both directions and omit empty values."""
    links = pagination_links(
        "/management/operator/users",
        filters={
            "q": "Ada Lovelace",
            "role": "admin",
            "active": False,
            "organization_id": None,
        },
        offset=20,
        limit=10,
        total=50,
    )

    assert links.previous_url is not None
    assert links.next_url is not None
    previous = urlsplit(links.previous_url)
    next_page = urlsplit(links.next_url)
    assert previous.path == next_page.path == "/management/operator/users"
    assert parse_qs(previous.query) == {
        "q": ["Ada Lovelace"],
        "role": ["admin"],
        "active": ["False"],
        "offset": ["10"],
        "limit": ["10"],
    }
    assert parse_qs(next_page.query) == {
        "q": ["Ada Lovelace"],
        "role": ["admin"],
        "active": ["False"],
        "offset": ["30"],
        "limit": ["10"],
    }


def test_pagination_links_stop_at_first_and_last_pages() -> None:
    """Do not expose links beyond the available result window."""
    first = pagination_links(
        "/management/organization/users",
        filters={},
        offset=0,
        limit=10,
        total=21,
    )
    last = pagination_links(
        "/management/organization/users",
        filters={},
        offset=20,
        limit=10,
        total=21,
    )

    assert first.previous_url is None
    assert first.next_url == "/management/organization/users?offset=10&limit=10"
    assert last.previous_url == "/management/organization/users?offset=10&limit=10"
    assert last.next_url is None
