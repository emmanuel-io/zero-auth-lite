"""Typed form models for organization-administrator browser actions."""

from app.identity.organizations.types import OrganizationName
from app.identity.users.enums import OrganizationMembershipRole
from app.identity.users.types import UserEmail, UserFirstName, UserLastName
from app.password.validation import PasswordInput
from app.web.management.forms import ManagementForm


class OrganizationUpdateForm(ManagementForm):
    """Validated organization metadata form fields."""

    name: OrganizationName


class OrganizationUserCreateForm(ManagementForm):
    """Validated organization user-creation form fields."""

    email: UserEmail
    first_name: UserFirstName = ""
    last_name: UserLastName = ""
    password: PasswordInput | None = None
    role: OrganizationMembershipRole = OrganizationMembershipRole.MEMBER
    is_active: bool = False


class OrganizationUserReplaceForm(ManagementForm):
    """Validated organization user-replacement form fields."""

    email: UserEmail
    first_name: UserFirstName = ""
    last_name: UserLastName = ""
    role: OrganizationMembershipRole = OrganizationMembershipRole.MEMBER
    is_active: bool = False
