"""Unit tests for application list query models."""

from datetime import date
from typing import Protocol

import pytest
from app.api.errors import StartDateAfterEndDateError
from app.api.v1.me.schemas import (
    CurrentUserBrowserSessionListQuery,
    CurrentUserOAuth2SessionListQuery,
)
from app.api.v1.organization.oauth2_sessions.schemas import (
    OrganizationOAuth2SessionListQuery,
)
from app.api.v1.organization.users.schemas import OrganizationUserSearchQuery
from app.api.v1.server.oauth2_clients.schemas import OAuth2ClientListQuery
from app.api.v1.server.organizations.schemas import ServerOrganizationListQuery
from app.api.v1.server.users.schemas import ServerUserSearchQuery
from app.identity.users.specs import UserSpecs
from pydantic import BaseModel, ValidationError


pytestmark = pytest.mark.unit
BROWSER_SESSION_LIST_LIMIT = 50


class PaginatedQuery(Protocol):
    """Structural type shared by paginated query models in this test."""

    offset: int
    limit: int


@pytest.mark.parametrize(
    ("query", "expected_offset", "expected_limit"),
    [
        (OrganizationUserSearchQuery(), 0, 20),
        (ServerUserSearchQuery(), 0, 20),
        (OrganizationOAuth2SessionListQuery(), 0, 100),
        (CurrentUserOAuth2SessionListQuery(), 0, 100),
        (ServerOrganizationListQuery(), 0, 20),
        (OAuth2ClientListQuery(), 0, 20),
    ],
)
def test_paginated_list_query_defaults(
    query: PaginatedQuery, expected_offset: int, expected_limit: int
) -> None:
    """Preserve each list endpoint's pagination defaults."""
    assert query.offset == expected_offset
    assert query.limit == expected_limit


def test_browser_session_list_query_defaults() -> None:
    """Preserve browser-session filtering and pagination defaults."""
    query = CurrentUserBrowserSessionListQuery()

    assert query.active_only is True
    assert query.offset == 0
    assert query.limit == BROWSER_SESSION_LIST_LIMIT


@pytest.mark.parametrize(
    "query_type",
    [
        OrganizationUserSearchQuery,
        ServerUserSearchQuery,
        OrganizationOAuth2SessionListQuery,
        CurrentUserOAuth2SessionListQuery,
        CurrentUserBrowserSessionListQuery,
        ServerOrganizationListQuery,
        OAuth2ClientListQuery,
    ],
)
def test_list_queries_reject_unknown_fields(query_type: type[BaseModel]) -> None:
    """Keep every application list query contract closed."""
    with pytest.raises(ValidationError, match="unexpected"):
        query_type.model_validate({"unexpected": "value"})


@pytest.mark.parametrize(
    ("query_type", "values"),
    [
        (OrganizationUserSearchQuery, {"offset": -1}),
        (ServerUserSearchQuery, {"limit": 101}),
        (OrganizationOAuth2SessionListQuery, {"limit": 0}),
        (CurrentUserOAuth2SessionListQuery, {"offset": -1}),
        (CurrentUserBrowserSessionListQuery, {"limit": 101}),
        (CurrentUserBrowserSessionListQuery, {"offset": -1}),
        (ServerOrganizationListQuery, {"limit": 0}),
        (OAuth2ClientListQuery, {"offset": -1}),
    ],
)
def test_list_queries_validate_pagination(
    query_type: type[BaseModel], values: dict[str, int]
) -> None:
    """Enforce existing pagination bounds through the query models."""
    with pytest.raises(ValidationError):
        query_type.model_validate(values)


def test_user_search_queries_preserve_filters() -> None:
    """Accept the complete organization and operator search filter sets."""
    organization_query = OrganizationUserSearchQuery(
        q="user",
        sort="-created_at",
        role="admin",
        active=True,
        email_verified=False,
    )
    server_query = ServerUserSearchQuery(
        q="user",
        sort="-operator",
        role="member",
        operator=True,
        organization_id="550e8400-e29b-41d4-a716-446655440000",
    )

    assert organization_query.sort == "-created_at"
    assert organization_query.email_verified is False
    assert server_query.sort == "-operator"
    assert str(server_query.organization_id) == "550e8400-e29b-41d4-a716-446655440000"


@pytest.mark.parametrize(
    "query_type", [OrganizationUserSearchQuery, ServerUserSearchQuery]
)
def test_user_search_queries_reject_inverted_date_ranges(
    query_type: type[OrganizationUserSearchQuery | ServerUserSearchQuery],
) -> None:
    """Retain the application error for inverted creation date ranges."""
    with pytest.raises(StartDateAfterEndDateError):
        query_type(
            created_from=date(2026, 8, 20),
            created_to=date(2026, 8, 19),
        )


@pytest.mark.parametrize(
    "query_type", [OrganizationUserSearchQuery, ServerUserSearchQuery]
)
def test_user_search_queries_reject_oversized_terms(
    query_type: type[OrganizationUserSearchQuery | ServerUserSearchQuery],
) -> None:
    """Bound search work before a query reaches SQLite."""
    with pytest.raises(ValidationError, match="q"):
        query_type(q="x" * (UserSpecs.SEARCH_QUERY_LENGTH_MAX + 1))


def test_identifier_and_sort_fields_remain_closed() -> None:
    """Reject malformed public identifiers and unsupported sort keys."""
    with pytest.raises(ValidationError, match="organization_id"):
        ServerUserSearchQuery(organization_id="invalid")
    with pytest.raises(ValidationError, match="user_id"):
        OrganizationOAuth2SessionListQuery(user_id="invalid")
    with pytest.raises(ValidationError, match="sort"):
        OrganizationUserSearchQuery.model_validate({"sort": "operator"})
