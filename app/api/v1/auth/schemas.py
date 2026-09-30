"""HTTP request schemas shared by authentication workflows."""

from typing import Annotated

from pydantic import BaseModel, ConfigDict, Field, UUID4

from app.identity.organizations.types import OrganizationName
from app.identity.users.enums import OrganizationMembershipRole
from app.identity.users.types import UserEmail, UserFirstName, UserLastName
from app.password.validation import StrongPassword
from app.workflow_tokens.specs import WorkflowTokenSpecs


class EmailRequest(BaseModel):
    """Request to trigger an authentication notification for an address."""

    model_config = ConfigDict(extra="forbid")

    email: Annotated[UserEmail, Field(description="User email address.")]


class RegisterRequest(BaseModel):
    """Request to create an organization and its initial administrator."""

    model_config = ConfigDict(extra="forbid")

    email: Annotated[UserEmail, Field(description="User email address.")]
    password: Annotated[
        StrongPassword,
        Field(description="User password.", json_schema_extra={"writeOnly": True}),
    ]
    first_name: Annotated[UserFirstName, Field(description="User first name.")] = ""
    last_name: Annotated[UserLastName, Field(description="User last name.")] = ""
    organization_name: Annotated[
        OrganizationName, Field(description="User organization name.")
    ]


class RegistrationResponse(BaseModel):
    """Public result of organization and initial-user registration."""

    public_id: UUID4 = Field(serialization_alias="id")
    organization_public_id: UUID4 = Field(serialization_alias="organization_id")
    email: str
    first_name: str
    last_name: str
    is_active: bool
    role: OrganizationMembershipRole
    email_verified: bool


class WorkflowTokenConfirmRequest(BaseModel):
    """Request containing a raw identity workflow token."""

    model_config = ConfigDict(extra="forbid")

    token: Annotated[
        str,
        Field(
            min_length=WorkflowTokenSpecs.RAW_TOKEN_LENGTH_MIN,
            max_length=WorkflowTokenSpecs.RAW_TOKEN_LENGTH_MAX,
            description="Raw identity workflow token.",
            json_schema_extra={"writeOnly": True},
        ),
    ]


class PasswordWorkflowTokenRequest(WorkflowTokenConfirmRequest):
    """Request containing a workflow token and a new password."""

    password: Annotated[
        StrongPassword,
        Field(
            description="New user password.",
            json_schema_extra={"writeOnly": True},
        ),
    ]
