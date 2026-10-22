"""Bounded inputs for server-rendered authentication workflows."""

from typing import Annotated

from fastapi import Query
from pydantic import BaseModel, ConfigDict, Field

from app.identity.organizations.specs import OrganizationSpecs
from app.identity.users.specs import UserSpecs
from app.oauth2.specs import OAuth2Specs
from app.password.validation import PasswordInput
from app.workflow_tokens.specs import WorkflowTokenSpecs


type BoundedEmail = Annotated[str, Field(max_length=UserSpecs.EMAIL_LENGTH_MAX)]


class AuthForm(BaseModel):
    """Browser form fields validated separately from CSRF authorization."""

    # Composed form models see each other's fields; retain ignored extras.
    model_config = ConfigDict(extra="ignore")

    csrf_token: str | None = None


class EmailRequestForm(AuthForm):
    """Email notification request with bounded, unnormalized input."""

    email: BoundedEmail


class LoginCredentialsForm(AuthForm):
    """Credentials submitted to the browser-session login service."""

    email: BoundedEmail
    password: PasswordInput


class RegistrationForm(AuthForm):
    """Registration input before domain validation and error redirects."""

    email: BoundedEmail
    password: PasswordInput
    organization_name: str = Field(max_length=OrganizationSpecs.NAME_LENGTH_MAX)
    first_name: str = Field(default="", max_length=UserSpecs.FIRST_NAME_LENGTH_MAX)
    last_name: str = Field(default="", max_length=UserSpecs.LAST_NAME_LENGTH_MAX)


class WorkflowTokenForm(AuthForm):
    """Confirmation token submitted from an email workflow page."""

    token: str = Field(
        min_length=WorkflowTokenSpecs.RAW_TOKEN_LENGTH_MIN,
        max_length=WorkflowTokenSpecs.RAW_TOKEN_LENGTH_MAX,
    )


class PasswordWorkflowForm(WorkflowTokenForm):
    """Password replacement shared by reset and invitation acceptance."""

    password: PasswordInput


class LoginContinuationForm(BaseModel):
    """Optional destinations submitted alongside login credentials."""

    model_config = ConfigDict(extra="ignore")

    transaction_id: str | None = Field(
        default=None, max_length=OAuth2Specs.PROTOCOL_VALUE_LENGTH_MAX
    )
    user_code: str | None = Field(
        default=None, max_length=OAuth2Specs.PROTOCOL_VALUE_LENGTH_MAX
    )
    return_url: str | None = Field(
        default=None, max_length=OAuth2Specs.PROTOCOL_VALUE_LENGTH_MAX
    )


class LoginContinuationQuery(BaseModel):
    """Login destinations supplied in a query string must be nonempty."""

    model_config = ConfigDict(extra="ignore")

    transaction_id: str | None = Field(
        default=None, min_length=1, max_length=OAuth2Specs.PROTOCOL_VALUE_LENGTH_MAX
    )
    user_code: str | None = Field(
        default=None, min_length=1, max_length=OAuth2Specs.PROTOCOL_VALUE_LENGTH_MAX
    )
    return_url: str | None = Field(
        default=None, min_length=1, max_length=OAuth2Specs.PROTOCOL_VALUE_LENGTH_MAX
    )


type WorkflowTokenQuery = Annotated[
    str,
    Query(
        min_length=WorkflowTokenSpecs.RAW_TOKEN_LENGTH_MIN,
        max_length=WorkflowTokenSpecs.RAW_TOKEN_LENGTH_MAX,
    ),
]
