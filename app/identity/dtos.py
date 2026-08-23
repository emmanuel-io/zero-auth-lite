"""Identity DTOs used at internal application boundaries."""

from dataclasses import dataclass
from datetime import datetime

from pydantic import BaseModel, ConfigDict

from app.identity.organizations.types import OrganizationName
from app.identity.users.enums import OrganizationUserRole
from app.identity.users.types import UserEmail, UserFirstName, UserLastName
from app.password.validation import StrongPassword
from app.public_ids import PublicId


class RegistrationCreateDTO(BaseModel):
    """Validated input for the canonical self-registration service."""

    model_config = ConfigDict(extra="forbid")

    email: UserEmail
    password: StrongPassword
    organization_name: OrganizationName
    first_name: UserFirstName = ""
    last_name: UserLastName = ""


@dataclass(frozen=True, slots=True)
class IdentityUserDTO:
    """User fields shared by canonical identity and authentication workflows.

    Internal IDs are used for application persistence relationships. Public IDs
    are stable identifiers suitable for external subjects and responses. The
    password field contains a password hash and must never contain raw password
    material.
    """

    id: int
    public_id: PublicId
    organization_id: int
    organization_public_id: PublicId
    email: str
    hashed_password: str
    first_name: str = ""
    last_name: str = ""
    pending_email: str | None = None
    is_active: bool = True
    email_verified: bool = False
    roles: tuple[str, ...] = ()
    sessions_invalid_before: datetime | None = None


@dataclass(frozen=True, slots=True)
class IdentityOrganizationDTO:
    """Organization fields shared by canonical identity workflows."""

    id: int
    public_id: PublicId
    name: str


@dataclass(frozen=True, slots=True)
class IdentityDTO:
    """Current application identity paired with its organization."""

    user: IdentityUserDTO
    organization: IdentityOrganizationDTO


@dataclass(frozen=True, slots=True)
class RegisteredUserDTO:
    """Safe registration result returned by the canonical server registration flow."""

    id: str
    organization_id: str
    email: str
    first_name: str
    last_name: str
    is_active: bool
    role: OrganizationUserRole
    email_verified: bool
