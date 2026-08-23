"""HTTP schemas for server-operator user administration routes."""

from datetime import datetime
from typing import Annotated

from pydantic import BaseModel, ConfigDict, Field, field_serializer, model_validator
from pydantic.json_schema import SkipJsonSchema

from app.api.schemas import reject_explicit_nulls
from app.identity.public_ids import (
    format_organization_id,
    format_user_id,
    ORGANIZATION_ID_PATTERN,
    USER_ID_PATTERN,
)
from app.identity.users.enums import OrganizationUserRole
from app.identity.users.types import UserEmail, UserFirstName, UserLastName
from app.public_ids import PublicId


class OperatorUserCreateRequest(BaseModel):
    """Server-user creation HTTP request."""

    model_config = ConfigDict(extra="forbid")

    email: UserEmail
    organization_id: Annotated[
        str,
        Field(
            description="Serialized organization identifier for the new user.",
            examples=["org_001P018WN3AT0"],
            pattern=ORGANIZATION_ID_PATTERN,
        ),
    ]
    first_name: UserFirstName = ""
    last_name: UserLastName = ""
    role: OrganizationUserRole = Field(default=OrganizationUserRole.MEMBER)
    is_operator: bool = Field(default=False, title="Is Operator")


class OperatorUserPatchRequest(BaseModel):
    """Server-user patch HTTP request."""

    model_config = ConfigDict(extra="forbid")

    email: UserEmail | SkipJsonSchema[None] = None
    first_name: UserFirstName | SkipJsonSchema[None] = None
    last_name: UserLastName | SkipJsonSchema[None] = None
    is_active: bool | SkipJsonSchema[None] = None
    role: OrganizationUserRole | SkipJsonSchema[None] = None
    organization_id: Annotated[
        str | SkipJsonSchema[None],
        Field(default=None, pattern=ORGANIZATION_ID_PATTERN),
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


class OperatorUserReplaceRequest(BaseModel):
    """Server-user replacement HTTP request."""

    model_config = ConfigDict(extra="forbid")

    organization_id: Annotated[str, Field(pattern=ORGANIZATION_ID_PATTERN)]
    email: UserEmail
    first_name: UserFirstName
    last_name: UserLastName
    is_active: bool
    role: OrganizationUserRole
    is_operator: bool
    email_verified: Annotated[
        bool, Field(description="Current email address is verified.")
    ]


class OperatorUserResponse(BaseModel):
    """Server-user HTTP response."""

    public_id: PublicId = Field(
        serialization_alias="id",
        json_schema_extra={"pattern": USER_ID_PATTERN},
    )
    organization_id: PublicId | None = Field(
        default=None,
        json_schema_extra={"pattern": ORGANIZATION_ID_PATTERN},
    )
    email: Annotated[UserEmail, Field(description="User email")]
    pending_email: Annotated[
        UserEmail | None,
        Field(description="Pending email address awaiting verification"),
    ] = None
    first_name: UserFirstName
    last_name: UserLastName
    is_active: bool
    role: OrganizationUserRole
    is_operator: bool = False
    email_verified: bool = False
    created_at: datetime
    updated_at: datetime

    @field_serializer("public_id")
    def serialize_public_id(self, value: PublicId) -> str:
        """Serialize the public user identifier."""
        return format_user_id(value)

    @field_serializer("organization_id")
    def serialize_organization_id(self, value: PublicId | None) -> str | None:
        """Serialize the public organization identifier when present."""
        return format_organization_id(value) if value is not None else None
