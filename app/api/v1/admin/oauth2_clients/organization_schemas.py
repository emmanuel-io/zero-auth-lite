"""HTTP schemas for OAuth2 client organization-access policies."""

from typing import Annotated

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.api.v1.admin.oauth2_clients.schema_validation import (
    OrganizationPublicId,
    reject_duplicates,
)
from app.oauth2.clients.access import (
    OAuth2ClientMachineOrganizationAccess,
    OAuth2ClientUserOrganizationAccess,
)
from app.oauth2.specs import OAuth2Specs


class OAuth2ClientUserOrganizationsRequest(BaseModel):
    """Replacement payload for a client's allowed user organizations."""

    model_config = ConfigDict(extra="forbid")

    organization_ids: Annotated[
        list[OrganizationPublicId],
        Field(max_length=OAuth2Specs.CLIENT_ORGANIZATION_ASSIGNMENTS_MAX),
    ]

    @field_validator("organization_ids")
    @classmethod
    def validate_unique_organization_ids(cls, value: list[str]) -> list[str]:
        """Reject duplicate public organization identifiers."""
        return reject_duplicates(value)


class OAuth2ClientUserOrganizationResponse(BaseModel):
    """One organization assigned to a global OAuth2 client."""

    organization_id: OrganizationPublicId
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
            list[OrganizationPublicId],
            Field(max_length=OAuth2Specs.CLIENT_ORGANIZATION_ASSIGNMENTS_MAX),
        ]
        | None
    ) = None

    @field_validator("organization_ids")
    @classmethod
    def validate_unique_organization_ids(
        cls, value: list[str] | None
    ) -> list[str] | None:
        """Reject duplicate public organization identifiers."""
        return reject_duplicates(value) if value is not None else None


class OAuth2ClientMachineOrganizationAccessResponse(BaseModel):
    """Current machine organization access policy and assignments."""

    client_id: str
    machine_organization_access: OAuth2ClientMachineOrganizationAccess
    organization_ids: list[OrganizationPublicId]
