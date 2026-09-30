"""HTTP schemas for current-organization user administration routes."""

from datetime import date, datetime
from typing import Annotated, Self

from fastapi import Query
from pydantic import BaseModel, ConfigDict, Field, model_validator, UUID4
from pydantic.json_schema import SkipJsonSchema

from app.api.dependencies.date_ranges import validate_date_range
from app.api.schemas import DEFAULT_PAGE_LIMIT_MAX, reject_explicit_nulls
from app.identity.users.criteria import (
    OrganizationMembershipRoleFilter,
    OrganizationUserSort,
)
from app.identity.users.enums import OrganizationMembershipRole
from app.identity.users.specs import UserSpecs
from app.identity.users.types import UserEmail, UserFirstName, UserLastName
from app.password.validation import (
    MAX_PASSWORD_LENGTH,
    MIN_PASSWORD_LENGTH,
    StrongPassword,
)


class OrganizationUserCreateRequest(BaseModel):
    """Organization-user creation HTTP request."""

    model_config = ConfigDict(extra="forbid")

    email: UserEmail
    password: Annotated[
        StrongPassword | None,
        Field(
            min_length=MIN_PASSWORD_LENGTH,
            max_length=MAX_PASSWORD_LENGTH,
            description=(
                "Initial password containing lowercase, uppercase, digit, and "
                "special characters. Omit it or send null to invite the user instead."
            ),
            json_schema_extra={"writeOnly": True},
        ),
    ] = None
    first_name: UserFirstName = ""
    last_name: UserLastName = ""
    is_active: bool = True
    role: OrganizationMembershipRole = Field(
        default=OrganizationMembershipRole.MEMBER,
        description="Role held by the user in the current organization.",
    )


class OrganizationUserPatchRequest(BaseModel):
    """Organization-user patch HTTP request."""

    model_config = ConfigDict(extra="forbid")

    email: UserEmail | SkipJsonSchema[None] = None
    first_name: UserFirstName | SkipJsonSchema[None] = None
    last_name: UserLastName | SkipJsonSchema[None] = None
    is_active: bool | SkipJsonSchema[None] = None
    role: OrganizationMembershipRole | SkipJsonSchema[None] = None

    @model_validator(mode="before")
    @classmethod
    def reject_explicit_nulls(cls, value: object) -> object:
        """Reject explicit nulls while allowing omitted fields."""
        return reject_explicit_nulls(value)


class OrganizationUserReplaceRequest(BaseModel):
    """Organization-user replacement HTTP request."""

    model_config = ConfigDict(extra="forbid")

    email: UserEmail
    first_name: UserFirstName
    last_name: UserLastName
    is_active: bool
    role: OrganizationMembershipRole


class OrganizationUserResponse(BaseModel):
    """Organization-user HTTP response."""

    public_id: UUID4 = Field(serialization_alias="id")
    email: Annotated[UserEmail, Field(description="User email")]
    pending_email: Annotated[
        UserEmail | None,
        Field(description="Pending email address awaiting verification"),
    ]
    first_name: Annotated[UserFirstName, Field(description="User first name")]
    last_name: Annotated[UserLastName, Field(description="User last name")]
    is_active: Annotated[bool, Field(description="User is active")]
    role: Annotated[
        OrganizationMembershipRole,
        Field(description="Role held by the user in the current organization."),
    ]
    email_verified: Annotated[
        bool, Field(description="Current email address is verified.")
    ]
    created_at: datetime
    updated_at: datetime


class OrganizationUserSearchQuery(BaseModel):
    """Query parameters for searching organization users."""

    model_config = ConfigDict(extra="forbid")

    q: str | None = Field(
        default=None,
        max_length=UserSpecs.SEARCH_QUERY_LENGTH_MAX,
        description="Case-insensitive search across names and email addresses.",
    )
    sort: OrganizationUserSort | None = Field(
        default=None,
        description="Sort field; values prefixed with '-' use descending order.",
    )
    role: OrganizationMembershipRoleFilter | None = Field(
        default=None, description="Organization membership role."
    )
    active: bool | None = Field(
        default=None, description="Filter by active account state."
    )
    email_verified: bool | None = Field(
        default=None, description="Filter by verified email state."
    )
    created_from: date | None = Field(
        default=None, description="Include users created on or after this UTC date."
    )
    created_to: date | None = Field(
        default=None, description="Include users created on or before this UTC date."
    )
    offset: int = Field(
        default=0, ge=0, description="Number of matching users to skip."
    )
    limit: int = Field(
        default=20,
        ge=1,
        le=DEFAULT_PAGE_LIMIT_MAX,
        description="Maximum number of users to return.",
    )

    @model_validator(mode="after")
    def validate_created_range(self) -> Self:
        """Validate the creation date range.

        Raises:
            StartDateAfterEndDateError: If the start date is later than the end date.
        """
        validate_date_range(start=self.created_from, end=self.created_to)

        return self


OrganizationUserSearchQueryDep = Annotated[OrganizationUserSearchQuery, Query()]
