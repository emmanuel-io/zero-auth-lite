"""HTTP schemas for server-wide user administration routes."""

from datetime import date, datetime
from typing import Annotated, Self

from fastapi import Query
from pydantic import BaseModel, ConfigDict, Field, model_validator, UUID4
from pydantic.json_schema import SkipJsonSchema

from app.api.dependencies.date_ranges import validate_date_range
from app.api.schemas import DEFAULT_PAGE_LIMIT_MAX, reject_explicit_nulls
from app.identity.users.criteria import OrganizationMembershipRoleFilter, ServerUserSort
from app.identity.users.enums import OrganizationMembershipRole
from app.identity.users.specs import UserSpecs
from app.identity.users.types import UserEmail, UserFirstName, UserLastName


class ServerUserCreateRequest(BaseModel):
    """Server-user creation HTTP request."""

    model_config = ConfigDict(extra="forbid")

    email: UserEmail
    organization_id: Annotated[
        UUID4,
        Field(
            description="Serialized organization identifier for the new user.",
            examples=["550e8400-e29b-41d4-a716-446655440000"],
        ),
    ]
    first_name: UserFirstName = ""
    last_name: UserLastName = ""
    role: OrganizationMembershipRole = Field(default=OrganizationMembershipRole.MEMBER)
    is_operator: bool = Field(default=False, title="Is Operator")


class ServerUserPatchRequest(BaseModel):
    """Server-user patch HTTP request."""

    model_config = ConfigDict(extra="forbid")

    email: UserEmail | SkipJsonSchema[None] = None
    first_name: UserFirstName | SkipJsonSchema[None] = None
    last_name: UserLastName | SkipJsonSchema[None] = None
    is_active: bool | SkipJsonSchema[None] = None
    role: OrganizationMembershipRole | SkipJsonSchema[None] = None
    organization_id: Annotated[
        UUID4 | SkipJsonSchema[None],
        Field(default=None),
    ] = None
    is_operator: Annotated[
        bool | SkipJsonSchema[None], Field(default=None, title="Is Operator")
    ] = None
    email_verified: Annotated[
        bool | SkipJsonSchema[None],
        Field(description="Current email address is verified."),
    ] = None

    @model_validator(mode="before")
    @classmethod
    def reject_explicit_nulls(cls, value: object) -> object:
        """Reject explicit nulls while allowing omitted fields."""
        return reject_explicit_nulls(value)


class ServerUserReplaceRequest(BaseModel):
    """Server-user replacement HTTP request."""

    model_config = ConfigDict(extra="forbid")

    organization_id: UUID4
    email: UserEmail
    first_name: UserFirstName
    last_name: UserLastName
    is_active: bool
    role: OrganizationMembershipRole
    is_operator: bool
    email_verified: Annotated[
        bool, Field(description="Current email address is verified.")
    ]


class ServerUserResponse(BaseModel):
    """Server-user HTTP response."""

    public_id: UUID4 = Field(serialization_alias="id")
    organization_id: UUID4
    email: Annotated[UserEmail, Field(description="User email")]
    pending_email: Annotated[
        UserEmail | None,
        Field(description="Pending email address awaiting verification"),
    ]
    first_name: UserFirstName
    last_name: UserLastName
    is_active: bool
    role: OrganizationMembershipRole
    is_operator: bool
    email_verified: bool
    created_at: datetime
    updated_at: datetime


class ServerUserSearchQuery(BaseModel):
    """Query parameters for searching users across organizations."""

    model_config = ConfigDict(extra="forbid")

    q: str | None = Field(
        default=None,
        max_length=UserSpecs.SEARCH_QUERY_LENGTH_MAX,
        description="Search name and email",
    )
    sort: ServerUserSort | None = Field(
        default=None,
        description="Sort key; prefix '-' selects descending order.",
    )
    role: OrganizationMembershipRoleFilter | None = Field(
        default=None, description="Organization membership role"
    )
    operator: bool | None = Field(default=None, description="Server-operator status")
    active: bool | None = Field(
        default=None, description="Filter by active account status."
    )
    email_verified: bool | None = Field(
        default=None, description="Filter by verified email status."
    )
    organization_id: UUID4 | None = Field(
        default=None,
        description="Organization UUID",
    )
    created_from: date | None = Field(
        default=None, description="Include users created on or after this date."
    )
    created_to: date | None = Field(
        default=None, description="Include users created on or before this date."
    )
    offset: int = Field(default=0, ge=0, description="Number of users to skip.")
    limit: int = Field(
        default=20,
        ge=1,
        le=DEFAULT_PAGE_LIMIT_MAX,
        description="Maximum users to return.",
    )

    @model_validator(mode="after")
    def validate_created_range(self) -> Self:
        """Validate the inclusive creation date range."""
        validate_date_range(start=self.created_from, end=self.created_to)
        return self


ServerUserSearchQueryDep = Annotated[ServerUserSearchQuery, Query()]
