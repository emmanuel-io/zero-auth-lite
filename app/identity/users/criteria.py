"""Typed criteria and results for user administration searches."""

from dataclasses import dataclass
from datetime import date
from typing import Literal, TypeAlias

from app.public_ids import PublicId


UserRoleFilter: TypeAlias = Literal["admin", "member"]  # noqa: UP040
OrganizationUserSort: TypeAlias = Literal[  # noqa: UP040
    "email",
    "-email",
    "first_name",
    "-first_name",
    "last_name",
    "-last_name",
    "active",
    "-active",
    "email_verified",
    "-email_verified",
    "created_at",
    "-created_at",
]
OperatorUserSort: TypeAlias = Literal[  # noqa: UP040
    "email",
    "-email",
    "first_name",
    "-first_name",
    "last_name",
    "-last_name",
    "active",
    "-active",
    "email_verified",
    "-email_verified",
    "operator",
    "-operator",
    "created_at",
    "-created_at",
]


@dataclass(frozen=True, slots=True)
class OrganizationUserSearchCriteriaDTO:
    """Search criteria accepted by organization user administration."""

    q: str | None = None
    sort: OrganizationUserSort | None = None
    role: UserRoleFilter | None = None
    active: bool | None = None
    email_verified: bool | None = None
    created_from: date | None = None
    created_to: date | None = None
    offset: int = 0
    limit: int = 20


@dataclass(frozen=True, slots=True)
class OperatorUserSearchCriteriaDTO:
    """Search criteria accepted by server-operator user administration."""

    q: str | None = None
    sort: OperatorUserSort | None = None
    role: UserRoleFilter | None = None
    operator: bool | None = None
    active: bool | None = None
    email_verified: bool | None = None
    organization_id: PublicId | None = None
    created_from: date | None = None
    created_to: date | None = None
    offset: int = 0
    limit: int = 20


@dataclass(frozen=True, slots=True)
class UserPageDTO[UserReadT]:
    """One page of users and its total matching count."""

    items: list[UserReadT]
    total: int
