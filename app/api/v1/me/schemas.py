"""HTTP schemas for current-user profile and account routes."""

from datetime import datetime
from typing import Annotated

from fastapi import Query
from pydantic import BaseModel, ConfigDict, Field, model_validator, UUID4
from pydantic.json_schema import SkipJsonSchema

from app.api.schemas import DEFAULT_PAGE_LIMIT_MAX, reject_explicit_nulls
from app.browser_sessions.specs import BrowserSessionSpecs
from app.identity.organizations.types import OrganizationName
from app.identity.users.enums import OrganizationMembershipRole
from app.identity.users.types import UserEmail, UserFirstName, UserLastName
from app.oauth2.grants.types import OAuth2SessionGrantType
from app.password.validation import PasswordInput, StrongPassword


class CurrentUserBrowserSessionListQuery(BaseModel):
    """Query parameters for listing the current user's browser sessions."""

    model_config = ConfigDict(extra="forbid")

    active_only: bool = True
    offset: int = Field(default=0, ge=0, description="Number of sessions to skip.")
    limit: int = Field(default=50, ge=1, le=DEFAULT_PAGE_LIMIT_MAX)


CurrentUserBrowserSessionListQueryDep = Annotated[
    CurrentUserBrowserSessionListQuery, Query()
]


class CurrentUserOAuth2SessionListQuery(BaseModel):
    """Query parameters for listing the current user's OAuth2 sessions."""

    model_config = ConfigDict(extra="forbid")

    offset: int = Field(default=0, ge=0, description="Number of sessions to skip.")
    limit: int = Field(default=100, ge=1, le=DEFAULT_PAGE_LIMIT_MAX)


CurrentUserOAuth2SessionListQueryDep = Annotated[
    CurrentUserOAuth2SessionListQuery, Query()
]


class CurrentUserOrganizationResponse(BaseModel):
    """Organization metadata embedded in the current-user response."""

    name: OrganizationName


class CurrentUserProfilePatchRequest(BaseModel):
    """Current-user profile patch HTTP request."""

    model_config = ConfigDict(extra="forbid")

    email: UserEmail | SkipJsonSchema[None] = None
    first_name: UserFirstName | SkipJsonSchema[None] = None
    last_name: UserLastName | SkipJsonSchema[None] = None

    @model_validator(mode="before")
    @classmethod
    def reject_explicit_nulls(cls, value: object) -> object:
        """Reject explicit nulls while allowing omitted fields."""
        return reject_explicit_nulls(value)


class CurrentUserProfileResponse(BaseModel):
    """Current-user profile HTTP response."""

    email: Annotated[UserEmail, Field(description="Current email address.")]
    pending_email: Annotated[
        UserEmail | None,
        Field(description="Pending email address awaiting verification."),
    ] = None
    first_name: UserFirstName
    last_name: UserLastName
    is_active: bool
    role: OrganizationMembershipRole
    email_verified: bool
    organization: Annotated[
        CurrentUserOrganizationResponse,
        Field(description="Organization associated with the current identity."),
    ]
    created_at: datetime
    updated_at: datetime


class CurrentUserPasswordChangeRequest(BaseModel):
    """Authenticated password-change HTTP request."""

    model_config = ConfigDict(extra="forbid")

    current_password: Annotated[
        PasswordInput,
        Field(min_length=1, json_schema_extra={"writeOnly": True}),
    ]
    new_password: Annotated[
        StrongPassword,
        Field(json_schema_extra={"writeOnly": True}),
    ]


class CurrentUserBrowserSessionResponse(BaseModel):
    """Browser session metadata returned to its owning user."""

    id: UUID4
    current: bool
    active: bool
    created_at: datetime
    last_seen_at: datetime
    expires_at: datetime
    absolute_expires_at: datetime
    revoked_at: datetime | None = None
    revoked_reason: Annotated[
        str | None,
        Field(max_length=BrowserSessionSpecs.REVOCATION_REASON_LENGTH_MAX),
    ] = None


class CurrentUserOAuth2SessionResponse(BaseModel):
    """One active OAuth2 session owned by the current user."""

    id: UUID4
    client_id: UUID4
    client_name: str
    client_active: bool
    grant_type: OAuth2SessionGrantType
    scopes: list[str]
    created_at: datetime
    last_token_issued_at: datetime
