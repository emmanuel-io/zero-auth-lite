"""User service data transfer objects."""

from datetime import datetime
from typing import Protocol

from pydantic import BaseModel, ConfigDict

from app.core.time import as_utc_aware
from app.identity.organizations.dtos import OrganizationSelfReadDTO
from app.identity.users.enums import OrganizationUserRole
from app.identity.users.types import UserEmail, UserFirstName, UserLastName
from app.password.validation import PasswordInput, StrongPassword
from app.public_ids import PublicId


class UserReadSourceProtocol(Protocol):
    """Structural source for building user read DTOs."""

    @property
    def public_id(self) -> PublicId | int:
        """Return the stable public user identifier."""
        ...

    @property
    def email(self) -> str:
        """Return the current email address."""
        ...

    @property
    def pending_email(self) -> str | None:
        """Return the pending email address."""
        ...

    first_name: str
    last_name: str
    is_active: bool
    is_operator: bool

    @property
    def email_verified(self) -> bool:
        """Return whether the current email is verified."""
        ...

    created_at: datetime
    updated_at: datetime


class OrganizationUserCreateDTO(BaseModel):
    """Organization-administrator user creation data."""

    model_config = ConfigDict(extra="forbid")

    email: UserEmail
    password: StrongPassword | None = None
    first_name: UserFirstName = ""
    last_name: UserLastName = ""
    is_active: bool = True
    role: OrganizationUserRole = OrganizationUserRole.MEMBER


class OperatorUserCreateDTO(BaseModel):
    """Server-operator invitation data."""

    model_config = ConfigDict(extra="forbid")

    email: UserEmail
    organization_id: PublicId
    first_name: UserFirstName = ""
    last_name: UserLastName = ""
    role: OrganizationUserRole = OrganizationUserRole.MEMBER
    is_operator: bool = False


class OrganizationUserPatchDTO(BaseModel):
    """Organization-administrator user partial update data."""

    model_config = ConfigDict(extra="forbid")

    email: UserEmail | None = None
    first_name: UserFirstName | None = None
    last_name: UserLastName | None = None
    is_active: bool | None = None
    role: OrganizationUserRole | None = None


class OrganizationUserReplaceDTO(BaseModel):
    """Organization-administrator full replacement data."""

    model_config = ConfigDict(extra="forbid")

    email: UserEmail
    first_name: UserFirstName
    last_name: UserLastName
    is_active: bool
    role: OrganizationUserRole


class OperatorUserPatchDTO(OrganizationUserPatchDTO):
    """Server-operator user partial update data."""

    organization_id: PublicId | None = None
    is_operator: bool | None = None
    email_verified: bool | None = None


class OperatorUserReplaceDTO(BaseModel):
    """Server-operator full replacement data."""

    model_config = ConfigDict(extra="forbid")

    organization_id: PublicId
    email: UserEmail
    first_name: UserFirstName
    last_name: UserLastName
    is_active: bool
    role: OrganizationUserRole
    is_operator: bool
    email_verified: bool


class UserSelfPatchDTO(BaseModel):
    """User self patch data."""

    model_config = ConfigDict(extra="forbid")

    email: UserEmail | None = None
    first_name: UserFirstName | None = None
    last_name: UserLastName | None = None


class UserSelfReadDTO(BaseModel):
    """Current-user profile without administration-only identifiers or roles."""

    model_config = ConfigDict(from_attributes=True)

    email: UserEmail
    pending_email: UserEmail | None = None
    first_name: UserFirstName
    last_name: UserLastName
    is_active: bool
    role: OrganizationUserRole
    email_verified: bool
    organization: OrganizationSelfReadDTO
    created_at: datetime
    updated_at: datetime


class UserPasswordChangeDTO(BaseModel):
    """Authenticated password-change service input."""

    model_config = ConfigDict(extra="forbid")

    current_password: PasswordInput
    new_password: StrongPassword


class UserReadDTO(BaseModel):
    """Read-only user data."""

    model_config = ConfigDict(from_attributes=True)

    public_id: PublicId

    email: UserEmail
    pending_email: UserEmail | None = None
    first_name: UserFirstName
    last_name: UserLastName
    is_active: bool
    role: OrganizationUserRole
    is_operator: bool = False
    email_verified: bool = False
    organization_id: PublicId | None = None
    created_at: datetime
    updated_at: datetime


class OrganizationUserReadDTO(BaseModel):
    """Organization-scoped administrative read model."""

    model_config = ConfigDict(from_attributes=True)

    public_id: PublicId

    email: UserEmail
    pending_email: UserEmail | None = None
    first_name: UserFirstName
    last_name: UserLastName
    is_active: bool
    role: OrganizationUserRole
    email_verified: bool = False
    created_at: datetime
    updated_at: datetime


def to_user_read_dto(
    user: UserReadSourceProtocol,
    organization_public_id: int | None,
    role: OrganizationUserRole,
) -> UserReadDTO:
    """Build a user read DTO with a public organization identifier."""
    return UserReadDTO(
        public_id=user.public_id,
        email=user.email,
        pending_email=getattr(user, "pending_email", None),
        first_name=user.first_name,
        last_name=user.last_name,
        is_active=user.is_active,
        role=role,
        is_operator=user.is_operator,
        email_verified=user.email_verified,
        organization_id=(
            PublicId(organization_public_id)
            if organization_public_id is not None
            else None
        ),
        created_at=as_utc_aware(user.created_at),
        updated_at=as_utc_aware(user.updated_at),
    )


def to_organization_user_read_dto(
    user: UserReadSourceProtocol,
    role: OrganizationUserRole,
) -> OrganizationUserReadDTO:
    """Build an organization-scoped read DTO without global-only fields."""
    return OrganizationUserReadDTO(
        public_id=user.public_id,
        email=user.email,
        pending_email=getattr(user, "pending_email", None),
        first_name=user.first_name,
        last_name=user.last_name,
        is_active=user.is_active,
        role=role,
        email_verified=user.email_verified,
        created_at=as_utc_aware(user.created_at),
        updated_at=as_utc_aware(user.updated_at),
    )


def to_user_self_read_dto(
    user: UserReadSourceProtocol,
    organization: OrganizationSelfReadDTO,
    role: OrganizationUserRole,
) -> UserSelfReadDTO:
    """Build the dedicated current-user profile response."""
    return UserSelfReadDTO(
        email=user.email,
        pending_email=getattr(user, "pending_email", None),
        first_name=user.first_name,
        last_name=user.last_name,
        is_active=user.is_active,
        role=role,
        email_verified=user.email_verified,
        organization=organization,
        created_at=as_utc_aware(user.created_at),
        updated_at=as_utc_aware(user.updated_at),
    )
