"""Typed form models for server-operator browser actions."""

from pydantic import Field, UUID4

from app.identity.organizations.types import OrganizationName
from app.identity.users.enums import OrganizationMembershipRole
from app.identity.users.types import UserEmail, UserFirstName, UserLastName
from app.oauth2.clients.access import (
    OAuth2ClientMachineOrganizationAccess,
    OAuth2ClientUserOrganizationAccess,
)
from app.oauth2.clients.types import OAuth2ClientName
from app.oauth2.grants.types import OAuth2GrantType
from app.oauth2.specs import OAuth2Specs
from app.web.management.forms import ManagementForm


class OperatorOrganizationCreateForm(ManagementForm):
    """Validated organization-creation form fields."""

    name: OrganizationName


class OperatorOrganizationUpdateForm(ManagementForm):
    """Validated organization-update form fields."""

    name: OrganizationName


class ServerUserCreateForm(ManagementForm):
    """Validated server user-creation form fields."""

    email: UserEmail
    organization_id: UUID4
    first_name: UserFirstName = ""
    last_name: UserLastName = ""
    role: OrganizationMembershipRole = OrganizationMembershipRole.MEMBER
    is_operator: bool = False


class ServerUserReplaceForm(ManagementForm):
    """Validated server user-replacement form fields."""

    email: UserEmail
    organization_id: UUID4
    first_name: UserFirstName = ""
    last_name: UserLastName = ""
    role: OrganizationMembershipRole = OrganizationMembershipRole.MEMBER
    is_active: bool = False
    is_operator: bool = False
    email_verified: bool = False


class OAuth2ClientRegistrationForm(ManagementForm):
    """Validated OAuth2 client-registration form fields."""

    name: OAuth2ClientName
    grant_types: tuple[OAuth2GrantType, ...]
    scopes: str = Field(default="", max_length=OAuth2Specs.SCOPE_LIST_LENGTH_MAX)
    redirect_uris: str = ""
    is_confidential: bool = False
    requires_consent: bool = False
    is_active: bool = False
    user_organization_access: OAuth2ClientUserOrganizationAccess = (
        OAuth2ClientUserOrganizationAccess.UNRESTRICTED
    )
    organization_ids: str = ""


class OAuth2ClientReplacementForm(ManagementForm):
    """Validated OAuth2 client-replacement form fields."""

    name: OAuth2ClientName
    grant_types: tuple[OAuth2GrantType, ...]
    scopes: str = Field(default="", max_length=OAuth2Specs.SCOPE_LIST_LENGTH_MAX)
    redirect_uris: str = ""
    is_confidential: bool = False
    requires_consent: bool = False
    is_active: bool = False


class UserOrganizationForm(ManagementForm):
    """Validated user access mode and organization assignments."""

    user_organization_access: OAuth2ClientUserOrganizationAccess
    organization_ids: str = ""


class MachineOrganizationForm(ManagementForm):
    """Validated machine access mode and organization assignments."""

    machine_organization_access: OAuth2ClientMachineOrganizationAccess
    organization_ids: str = ""
