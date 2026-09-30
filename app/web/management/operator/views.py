"""Typed template models for the server-operator interface."""

from dataclasses import dataclass

from app.identity.organizations.dtos import OrganizationReadDTO
from app.identity.users.dtos import UserReadDTO
from app.identity.users.enums import OrganizationMembershipRole
from app.oauth2.clients.access import (
    OAuth2ClientMachineOrganizationAccess,
    OAuth2ClientUserOrganizationAccess,
)
from app.oauth2.clients.dtos import OAuth2ClientReadDTO


@dataclass(frozen=True, slots=True)
class OrganizationView:
    """Organization fields rendered by operator templates."""

    id: str
    name: str

    @classmethod
    def from_dto(cls, item: OrganizationReadDTO) -> "OrganizationView":
        """Build a template model from the service DTO."""
        return cls(id=str(item.public_id), name=item.name)


@dataclass(frozen=True, slots=True)
class ServerUserView:
    """User fields rendered by operator templates."""

    id: str
    organization_id: str | None
    email: str
    pending_email: str | None
    first_name: str
    last_name: str
    is_active: bool
    role: OrganizationMembershipRole
    is_operator: bool
    email_verified: bool

    @classmethod
    def from_dto(cls, item: UserReadDTO) -> "ServerUserView":
        """Build a template model from the service DTO."""
        return cls(
            id=str(item.public_id),
            organization_id=str(item.organization_public_id),
            email=str(item.email),
            pending_email=str(item.pending_email) if item.pending_email else None,
            first_name=item.first_name,
            last_name=item.last_name,
            is_active=item.is_active,
            role=item.role,
            is_operator=item.is_operator,
            email_verified=item.email_verified,
        )


@dataclass(frozen=True, slots=True)
class OAuth2ClientView:
    """OAuth2 client fields rendered by operator templates."""

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

    @classmethod
    def from_dto(cls, item: OAuth2ClientReadDTO) -> "OAuth2ClientView":
        """Build a template model from the service DTO."""
        return cls(
            client_id=str(item.client_id),
            name=item.name,
            grant_types=item.grant_types,
            scopes=list(item.scopes),
            redirect_uris=list(item.redirect_uris or []),
            is_confidential=item.is_confidential,
            requires_consent=item.requires_consent,
            is_active=item.is_active,
            user_organization_access=item.user_organization_access,
            machine_organization_access=item.machine_organization_access,
        )
