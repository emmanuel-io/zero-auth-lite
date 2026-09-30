"""Shared SQL construction for user-administration searches."""

from collections.abc import Mapping
from typing import Any

from sqlalchemy import and_, func
from sqlalchemy.orm import aliased
from sqlalchemy.sql import ColumnElement, Select

from app.db.models.organization_membership import OrganizationMembershipDB
from app.db.models.user import UserDB, UserEmailDB
from app.identity.users.criteria import UserSearchCriteriaDTO
from app.identity.users.enums import UserEmailStatus
from app.identity.users.query import (
    boolean_state_filter,
    compact_filters,
    created_window_filter,
    parse_sort,
    search_filter,
    SortValue,
)


CurrentEmail = aliased(UserEmailDB, name="current_email")
PendingEmail = aliased(UserEmailDB, name="pending_email")


def join_user_search_emails[SelectedRow: tuple[Any, ...]](
    statement: Select[SelectedRow],
) -> Select[SelectedRow]:
    """Join the current and optional pending email used by user searches."""
    return statement.join(
        CurrentEmail,
        and_(
            CurrentEmail.user_id == UserDB.id,
            CurrentEmail.status == UserEmailStatus.CURRENT,
        ),
    ).outerjoin(
        PendingEmail,
        and_(
            PendingEmail.user_id == UserDB.id,
            PendingEmail.status == UserEmailStatus.PENDING,
        ),
    )


def user_search_filters(
    *,
    criteria: UserSearchCriteriaDTO,
) -> list[ColumnElement[bool]]:
    """Build filters shared by organization and operator user searches."""
    return compact_filters(
        search_filter(
            q=criteria.q,
            columns=(
                CurrentEmail.email,
                PendingEmail.email,
                UserDB.first_name,
                UserDB.last_name,
            ),
        ),
        OrganizationMembershipDB.role == criteria.role
        if criteria.role is not None
        else None,
        boolean_state_filter(UserDB.is_active, value=criteria.active),
        (
            CurrentEmail.verified_at.is_not(None)
            if criteria.email_verified is True
            else CurrentEmail.verified_at.is_(None)
            if criteria.email_verified is False
            else None
        ),
        created_window_filter(
            column=UserDB.created_at,
            created_from=criteria.created_from,
            created_to=criteria.created_to,
        ),
    )


def apply_user_search_sort[SelectedRow: tuple[Any, ...]](
    statement: Select[SelectedRow],
    *,
    sort: str | None,
    additional_sorts: Mapping[str, SortValue] | None = None,
) -> Select[SelectedRow]:
    """Apply shared user sorts plus explicitly supplied service-specific sorts."""
    allowed: dict[str, SortValue] = {
        "email": (func.lower(CurrentEmail.email), UserDB.id),
        "first_name": (func.lower(UserDB.first_name), UserDB.id),
        "last_name": (func.lower(UserDB.last_name), UserDB.id),
        "active": (UserDB.is_active, UserDB.id),
        "email_verified": (CurrentEmail.verified_at.is_not(None), UserDB.id),
        "created_at": (UserDB.created_at, UserDB.id),
    }
    if additional_sorts is not None:
        allowed.update(additional_sorts)
    order_by = parse_sort(
        sort=sort,
        allowed=allowed,
        default=(UserDB.created_at.desc(), UserDB.id.desc()),
    )
    return statement.order_by(*order_by)
