"""Typed criteria and results for user administration searches."""

from dataclasses import dataclass
from datetime import date
from typing import Literal, TypeAlias
from uuid import UUID


# FastAPI inspects these aliases at runtime when building the query-parameter
# schema and does not currently resolve their PEP 695 ``TypeAliasType`` form.
OrganizationMembershipRoleFilter: TypeAlias = Literal[  # noqa: UP040
    "admin", "member"
]
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
ServerUserSort: TypeAlias = Literal[  # noqa: UP040
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
    role: OrganizationMembershipRoleFilter | None = None
    active: bool | None = None
    email_verified: bool | None = None
    created_from: date | None = None
    created_to: date | None = None
    offset: int = 0
    limit: int = 20


@dataclass(frozen=True, slots=True)
class ServerUserSearchCriteriaDTO:
    """Search criteria accepted by server-operator user administration."""

    q: str | None = None
    sort: ServerUserSort | None = None
    role: OrganizationMembershipRoleFilter | None = None
    operator: bool | None = None
    active: bool | None = None
    email_verified: bool | None = None
    organization_id: UUID | None = None
    created_from: date | None = None
    created_to: date | None = None
    offset: int = 0
    limit: int = 20


type UserSearchCriteriaDTO = (
    OrganizationUserSearchCriteriaDTO | ServerUserSearchCriteriaDTO
)


@dataclass(frozen=True, slots=True)
class UserPageDTO[UserReadT]:
    """One page of users and its total matching count."""

    items: list[UserReadT]
    total: int
