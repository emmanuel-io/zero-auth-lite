"""HTTP schemas for current-organization user administration routes."""

from datetime import datetime
from typing import Annotated

from pydantic import BaseModel, ConfigDict, Field, field_serializer, model_validator
from pydantic.json_schema import SkipJsonSchema

from app.api.schemas import reject_explicit_nulls
from app.identity.public_ids import (
    format_user_id,
    USER_ID_PATTERN,
)
from app.identity.users.enums import OrganizationUserRole
from app.identity.users.types import UserEmail, UserFirstName, UserLastName
from app.password.validation import (
    MAX_PASSWORD_LENGTH,
    MIN_PASSWORD_LENGTH,
    StrongPassword,
)
from app.public_ids import PublicId


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
    role: OrganizationUserRole = Field(
        default=OrganizationUserRole.MEMBER,
        description="Role held by the user in the current organization.",
    )


class OrganizationUserPatchRequest(BaseModel):
    """Organization-user patch HTTP request."""

    model_config = ConfigDict(extra="forbid")

    email: UserEmail | SkipJsonSchema[None] = None
    first_name: UserFirstName | SkipJsonSchema[None] = None
    last_name: UserLastName | SkipJsonSchema[None] = None
    is_active: bool | SkipJsonSchema[None] = None
    role: OrganizationUserRole | SkipJsonSchema[None] = None

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
    role: OrganizationUserRole


class OrganizationUserResponse(BaseModel):
    """Organization-user HTTP response."""

    public_id: PublicId = Field(
        serialization_alias="id",
        json_schema_extra={"pattern": USER_ID_PATTERN},
    )
    email: Annotated[UserEmail, Field(description="User email")]
    pending_email: Annotated[
        UserEmail | None,
        Field(description="Pending email address awaiting verification"),
    ] = None
    first_name: Annotated[UserFirstName, Field(description="User first name")]
    last_name: Annotated[UserLastName, Field(description="User last name")]
    is_active: Annotated[bool, Field(description="User is active")]
    role: Annotated[
        OrganizationUserRole,
        Field(description="Role held by the user in the current organization."),
    ]
    email_verified: Annotated[
        bool, Field(description="Current email address is verified.")
    ] = False
    created_at: datetime
    updated_at: datetime

    @field_serializer("public_id")
    def serialize_public_id(self, value: PublicId) -> str:
        """Serialize the public user identifier."""
        return format_user_id(value)
