"""HTTP schemas and validation for OAuth2 client administration."""

from typing import Annotated

from fastapi import Query
from pydantic import BaseModel, ConfigDict, Field, field_validator, HttpUrl, UUID4

from app.api.schemas import DEFAULT_PAGE_LIMIT_MAX
from app.oauth2.clients.access import (
    OAuth2ClientMachineOrganizationAccess,
    OAuth2ClientUserOrganizationAccess,
)
from app.oauth2.clients.redirect_uris import validate_redirect_uris
from app.oauth2.clients.types import OAuth2ClientName
from app.oauth2.grants.types import OAuth2GrantType
from app.oauth2.scopes import ScopeName
from app.oauth2.specs import OAuth2Specs


RedirectUri = Annotated[HttpUrl, Field(max_length=OAuth2Specs.REDIRECT_URI_LENGTH_MAX)]


def reject_duplicates[T](values: list[T]) -> list[T]:
    """Reject repeated client configuration values."""
    normalized = [str(value) for value in values]
    if len(normalized) != len(set(normalized)):
        msg = "duplicate_values_not_allowed"
        raise ValueError(msg)
    return values


class OAuth2ClientListQuery(BaseModel):
    """Query parameters for listing global OAuth2 clients."""

    model_config = ConfigDict(extra="forbid")

    offset: int = Field(default=0, ge=0)
    limit: int = Field(default=20, ge=1, le=DEFAULT_PAGE_LIMIT_MAX)


OAuth2ClientListQueryDep = Annotated[OAuth2ClientListQuery, Query()]


class OAuth2ClientCreateRequest(BaseModel):
    """Request payload for creating an OAuth2 client."""

    model_config = ConfigDict(extra="forbid")

    name: OAuth2ClientName
    grant_types: list[OAuth2GrantType]
    scopes: list[ScopeName] = Field(default_factory=list)
    redirect_uris: list[RedirectUri] = Field(default_factory=list)
    is_confidential: bool = False
    requires_consent: bool = True
    is_active: bool = True
    user_organization_access: OAuth2ClientUserOrganizationAccess = Field(
        default=OAuth2ClientUserOrganizationAccess.UNRESTRICTED,
        description=(
            "Organization access policy for user-backed grants; "
            "it does not apply to client_credentials."
        ),
    )
    user_organization_ids: Annotated[
        list[UUID4],
        Field(max_length=OAuth2Specs.CLIENT_ORGANIZATION_ASSIGNMENTS_MAX),
    ] = Field(
        default_factory=list,
        description="Organization assignments applied atomically with the access mode.",
    )

    @field_validator("redirect_uris")
    @classmethod
    def validate_redirect_uris(cls, value: list[HttpUrl]) -> list[HttpUrl]:
        """Validate registered redirect URIs."""
        return validate_redirect_uris(value)

    @field_validator("grant_types", "scopes", "user_organization_ids")
    @classmethod
    def validate_unique_values[T](cls, value: list[T]) -> list[T]:
        """Reject duplicate grants and scopes."""
        return reject_duplicates(value)


class OAuth2ClientReplaceRequest(BaseModel):
    """Request payload for replacing an OAuth2 client."""

    model_config = ConfigDict(extra="forbid")

    name: OAuth2ClientName
    grant_types: list[OAuth2GrantType]
    scopes: list[ScopeName]
    redirect_uris: list[RedirectUri]
    is_confidential: bool
    requires_consent: bool
    is_active: bool

    @field_validator("redirect_uris")
    @classmethod
    def validate_redirect_uris(cls, value: list[HttpUrl]) -> list[HttpUrl]:
        """Validate registered redirect URIs."""
        return validate_redirect_uris(value)

    @field_validator("grant_types", "scopes")
    @classmethod
    def validate_unique_values[T](cls, value: list[T]) -> list[T]:
        """Reject duplicate grants and scopes."""
        return reject_duplicates(value)


class OAuth2ClientReadResponse(BaseModel):
    """Response payload for reading an OAuth2 client."""

    client_id: UUID4
    name: str
    grant_types: list[str]
    scopes: list[str]
    redirect_uris: list[str]
    is_confidential: bool
    requires_consent: bool
    is_active: bool
    user_organization_access: OAuth2ClientUserOrganizationAccess
    machine_organization_access: OAuth2ClientMachineOrganizationAccess


class OAuth2ClientCreateResponse(OAuth2ClientReadResponse):
    """Response payload for creating an OAuth2 client."""

    client_secret: Annotated[
        str | None,
        Field(
            description=(
                "Raw secret returned once for a confidential client. It cannot "
                "be retrieved after this response."
            )
        ),
    ] = None


class OAuth2ClientUserOrganizationsRequest(BaseModel):
    """Replacement payload for a client's allowed user organizations."""

    model_config = ConfigDict(extra="forbid")

    user_organization_access: OAuth2ClientUserOrganizationAccess
    organization_ids: Annotated[
        list[UUID4],
        Field(max_length=OAuth2Specs.CLIENT_ORGANIZATION_ASSIGNMENTS_MAX),
    ]

    @field_validator("organization_ids")
    @classmethod
    def validate_unique_organization_ids(cls, value: list[UUID4]) -> list[UUID4]:
        """Reject duplicate public organization identifiers."""
        return reject_duplicates(value)


class OAuth2ClientUserOrganizationResponse(BaseModel):
    """One organization assigned to a global OAuth2 client."""

    organization_id: UUID4
    name: str | None


class OAuth2ClientUserOrganizationsResponse(BaseModel):
    """Current user-organization policy and its explicit assignments."""

    user_organization_access: OAuth2ClientUserOrganizationAccess
    organizations: list[OAuth2ClientUserOrganizationResponse]


class OAuth2ClientMachineOrganizationAccessRequest(BaseModel):
    """Atomic machine organization access policy replacement."""

    model_config = ConfigDict(extra="forbid")

    machine_organization_access: OAuth2ClientMachineOrganizationAccess
    organization_ids: (
        Annotated[
            list[UUID4],
            Field(max_length=OAuth2Specs.CLIENT_ORGANIZATION_ASSIGNMENTS_MAX),
        ]
        | None
    ) = None

    @field_validator("organization_ids")
    @classmethod
    def validate_unique_organization_ids(
        cls, value: list[UUID4] | None
    ) -> list[UUID4] | None:
        """Reject duplicate public organization identifiers."""
        return reject_duplicates(value) if value is not None else None


class OAuth2ClientMachineOrganizationAccessResponse(BaseModel):
    """Current machine organization access policy and assignments."""

    client_id: UUID4
    machine_organization_access: OAuth2ClientMachineOrganizationAccess
    organization_ids: list[UUID4]


class OAuth2ClientSecretResponse(BaseModel):
    """Response payload for creating a replacement OAuth2 client secret."""

    client_id: Annotated[UUID4, Field(description="Global OAuth2 client UUID.")]
    client_secret: Annotated[
        str,
        Field(
            description=(
                "Raw replacement secret returned once. It cannot be retrieved "
                "after this response."
            )
        ),
    ]
