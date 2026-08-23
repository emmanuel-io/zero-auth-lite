"""HTTP request schemas shared by authentication workflows."""

from typing import Annotated

from pydantic import BaseModel, ConfigDict, Field

from app.auth_tokens.specs import AuthTokenSpecs
from app.identity.organizations.types import OrganizationName
from app.identity.users.enums import OrganizationUserRole
from app.identity.users.types import UserEmail, UserFirstName, UserLastName
from app.password.validation import StrongPassword


class EmailRequest(BaseModel):
    """Request to trigger an authentication notification for an address."""

    model_config = ConfigDict(extra="forbid")

    email: Annotated[UserEmail, Field(description="User email address.")]


class RegisterRequest(BaseModel):
    """Request to create an organization and its initial administrator."""

    model_config = ConfigDict(extra="forbid")

    email: Annotated[UserEmail, Field(description="User email address.")]
    password: Annotated[StrongPassword, Field(description="User password.")]
    first_name: Annotated[UserFirstName, Field(description="User first name.")] = ""
    last_name: Annotated[UserLastName, Field(description="User last name.")] = ""
    organization_name: Annotated[
        OrganizationName, Field(description="User organization name.")
    ]


class RegistrationResponse(BaseModel):
    """Public result of organization and initial-user registration."""

    id: str
    organization_id: str
    email: str
    first_name: str
    last_name: str
    is_active: bool
    role: OrganizationUserRole
    email_verified: bool


class TokenConfirmRequest(BaseModel):
    """Request containing a raw authentication workflow token."""

    model_config = ConfigDict(extra="forbid")

    token: Annotated[
        str,
        Field(
            min_length=AuthTokenSpecs.RAW_TOKEN_LENGTH_MIN,
            max_length=AuthTokenSpecs.RAW_TOKEN_LENGTH_MAX,
            description="Raw auth token.",
        ),
    ]


class PasswordTokenRequest(TokenConfirmRequest):
    """Request containing a workflow token and a new password."""

    password: Annotated[StrongPassword, Field(description="New user password.")]
