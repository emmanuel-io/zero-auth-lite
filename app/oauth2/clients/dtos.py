"""OAuth2 client service data transfer objects."""

from dataclasses import dataclass
from typing import Annotated

from pydantic import BaseModel, ConfigDict, Field

from app.oauth2.clients.access import (
    OAuth2ClientMachineOrganizationAccess,
    OAuth2ClientUserOrganizationAccess,
)
from app.oauth2.clients.types import OAuth2ClientName
from app.oauth2.scopes import ScopeName
from app.oauth2.specs import OAuth2Specs


RedirectUriString = Annotated[
    str,
    Field(max_length=OAuth2Specs.REDIRECT_URI_LENGTH_MAX),
]


class _StrictDTO(BaseModel):
    """Base model that rejects service-boundary field drift."""

    model_config = ConfigDict(extra="forbid")


class OAuth2ClientPersistenceCreateDTO(_StrictDTO):
    """OAuth2 client creation data."""

    client_id: Annotated[str, Field(max_length=OAuth2Specs.CLIENT_ID_LENGTH_MAX)]
    client_secret: str | None
    name: OAuth2ClientName
    grant_types: list[str]
    scopes: list[ScopeName]
    redirect_uris: list[RedirectUriString] | None
    is_confidential: bool = True
    requires_consent: bool = True
    is_active: bool = True
    user_organization_access: OAuth2ClientUserOrganizationAccess = (
        OAuth2ClientUserOrganizationAccess.UNRESTRICTED
    )
    machine_organization_access: OAuth2ClientMachineOrganizationAccess = (
        OAuth2ClientMachineOrganizationAccess.NONE
    )


class OAuth2ClientRegistrationDTO(_StrictDTO):
    """Validated client registration input accepted by the service."""

    name: OAuth2ClientName
    grant_types: list[str]
    scopes: list[ScopeName]
    redirect_uris: list[RedirectUriString]
    is_confidential: bool = False
    requires_consent: bool = True
    is_active: bool = True
    user_organization_access: OAuth2ClientUserOrganizationAccess = (
        OAuth2ClientUserOrganizationAccess.UNRESTRICTED
    )


class OAuth2ClientPersistenceUpdateDTO(_StrictDTO):
    """OAuth2 client update data."""

    client_secret: str | None
    name: OAuth2ClientName
    grant_types: list[str]
    scopes: list[ScopeName]
    redirect_uris: list[RedirectUriString] | None
    is_confidential: bool
    requires_consent: bool
    is_active: bool
    user_organization_access: OAuth2ClientUserOrganizationAccess = (
        OAuth2ClientUserOrganizationAccess.UNRESTRICTED
    )
    machine_organization_access: OAuth2ClientMachineOrganizationAccess = (
        OAuth2ClientMachineOrganizationAccess.NONE
    )


class OAuth2ClientRegistryReplaceDTO(_StrictDTO):
    """Validated client replacement accepted by the registry service."""

    name: OAuth2ClientName
    grant_types: list[str]
    scopes: list[ScopeName]
    redirect_uris: list[RedirectUriString]
    is_confidential: bool
    requires_consent: bool
    is_active: bool
    user_organization_access: OAuth2ClientUserOrganizationAccess


class OAuth2ClientMachineOrganizationUpdateDTO(_StrictDTO):
    """Atomic machine-organization policy replacement input."""

    machine_organization_access: OAuth2ClientMachineOrganizationAccess
    organization_ids: (
        Annotated[
            list[str],
            Field(max_length=OAuth2Specs.CLIENT_ORGANIZATION_ASSIGNMENTS_MAX),
        ]
        | None
    ) = None


class OAuth2ClientReadDTO(_StrictDTO):
    """Internal OAuth2 client representation returned by services."""

    client_id: str
    client_secret: str | None
    name: OAuth2ClientName
    grant_types: list[str]
    scopes: list[ScopeName]
    redirect_uris: list[RedirectUriString] | None
    is_confidential: bool
    requires_consent: bool
    is_active: bool
    user_organization_access: OAuth2ClientUserOrganizationAccess = (
        OAuth2ClientUserOrganizationAccess.UNRESTRICTED
    )
    machine_organization_access: OAuth2ClientMachineOrganizationAccess = (
        OAuth2ClientMachineOrganizationAccess.NONE
    )

    model_config = ConfigDict(extra="forbid", from_attributes=True)
    """Pydantic model configuration."""


@dataclass(frozen=True, slots=True)
class OAuth2ClientCreateResultDTO:
    """New client registration and its one-time raw secret."""

    client: OAuth2ClientReadDTO
    client_secret: str | None


@dataclass(frozen=True, slots=True)
class OAuth2ClientSecretDTO:
    """One-time replacement credential returned by the credential service."""

    client_id: str
    client_secret: str


@dataclass(frozen=True, slots=True)
class OAuth2ClientOrganizationDTO:
    """Public organization identity attached to an OAuth2 client policy."""

    organization_id: str
    name: str | None


@dataclass(frozen=True, slots=True)
class OAuth2ClientUserOrganizationsDTO:
    """User-backed organization policy and its explicit assignments."""

    user_organization_access: OAuth2ClientUserOrganizationAccess
    organizations: list[OAuth2ClientOrganizationDTO]


@dataclass(frozen=True, slots=True)
class OAuth2ClientMachineOrganizationsDTO:
    """Machine organization policy and its explicit assignments."""

    client_id: str
    machine_organization_access: OAuth2ClientMachineOrganizationAccess
    organization_ids: list[str]
