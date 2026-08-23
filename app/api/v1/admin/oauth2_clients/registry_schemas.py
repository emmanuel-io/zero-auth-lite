"""HTTP schemas for the global OAuth2 client registry."""

from typing import Annotated

from pydantic import BaseModel, ConfigDict, Field, field_validator, HttpUrl

from app.api.v1.admin.oauth2_clients.schema_validation import (
    RedirectUri,
    reject_duplicates,
    validate_redirect_uris,
)
from app.oauth2.clients.access import (
    OAuth2ClientMachineOrganizationAccess,
    OAuth2ClientUserOrganizationAccess,
)
from app.oauth2.clients.dtos import (
    OAuth2ClientCreateResultDTO,
    OAuth2ClientReadDTO,
    OAuth2ClientRegistrationDTO,
    OAuth2ClientRegistryReplaceDTO,
)
from app.oauth2.clients.types import OAuth2ClientName
from app.oauth2.scopes import ScopeName
from app.oauth2.settings import OAuth2GrantType


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

    @field_validator("redirect_uris")
    @classmethod
    def validate_redirect_uris(cls, value: list[HttpUrl]) -> list[HttpUrl]:
        """Validate registered redirect URIs."""
        return validate_redirect_uris(reject_duplicates(value))

    @field_validator("grant_types", "scopes")
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
    user_organization_access: OAuth2ClientUserOrganizationAccess = Field(
        description=(
            "Organization access policy for user-backed grants; "
            "it does not apply to client_credentials."
        ),
    )

    @field_validator("redirect_uris")
    @classmethod
    def validate_redirect_uris(cls, value: list[HttpUrl]) -> list[HttpUrl]:
        """Validate registered redirect URIs."""
        return validate_redirect_uris(reject_duplicates(value))

    @field_validator("grant_types", "scopes")
    @classmethod
    def validate_unique_values[T](cls, value: list[T]) -> list[T]:
        """Reject duplicate grants and scopes."""
        return reject_duplicates(value)


class OAuth2ClientReadResponse(BaseModel):
    """Response payload for reading an OAuth2 client."""

    client_id: str
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


def client_registration_dto(
    payload: OAuth2ClientCreateRequest,
) -> OAuth2ClientRegistrationDTO:
    """Convert an HTTP creation payload to a service DTO."""
    return OAuth2ClientRegistrationDTO(
        **payload.model_dump(exclude={"grant_types", "redirect_uris"}),
        grant_types=[grant.value for grant in payload.grant_types],
        redirect_uris=[str(uri) for uri in payload.redirect_uris],
    )


def client_replace_dto(
    payload: OAuth2ClientReplaceRequest,
) -> OAuth2ClientRegistryReplaceDTO:
    """Convert an HTTP replacement payload to a service DTO."""
    return OAuth2ClientRegistryReplaceDTO(
        **payload.model_dump(exclude={"grant_types", "redirect_uris"}),
        grant_types=[grant.value for grant in payload.grant_types],
        redirect_uris=[str(uri) for uri in payload.redirect_uris],
    )


def client_response(dto: OAuth2ClientReadDTO) -> OAuth2ClientReadResponse:
    """Convert a client service DTO to its public response."""
    return OAuth2ClientReadResponse(
        **dto.model_dump(exclude={"client_secret", "redirect_uris"}),
        redirect_uris=dto.redirect_uris or [],
    )


def client_create_response(
    dto: OAuth2ClientCreateResultDTO,
) -> OAuth2ClientCreateResponse:
    """Convert a registration result to its one-time HTTP response."""
    return OAuth2ClientCreateResponse(
        **client_response(dto.client).model_dump(),
        client_secret=dto.client_secret,
    )
