"""Typed commands consumed by the actor-neutral user lifecycle."""

from enum import StrEnum
from typing import cast

from pydantic import BaseModel, ConfigDict, model_validator

from app.identity.users.enums import OrganizationUserRole
from app.identity.users.types import UserEmail, UserFirstName, UserLastName
from app.password.validation import StrongPassword


class UserOnboardingMode(StrEnum):
    """Define how a newly created user proves control of the account."""

    INVITATION = "invitation"
    PASSWORD_VERIFICATION = "password_verification"  # noqa: S105


class UserCreateCommand(BaseModel):
    """Complete actor-neutral input for creating one user."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    organization_id: int
    email: UserEmail
    onboarding: UserOnboardingMode
    password: StrongPassword | None = None
    first_name: UserFirstName = ""
    last_name: UserLastName = ""
    is_active: bool = True
    role: OrganizationUserRole = OrganizationUserRole.MEMBER
    is_operator: bool = False
    email_verified: bool = False

    @model_validator(mode="after")
    def validate_onboarding_credentials(self) -> "UserCreateCommand":
        """Keep the selected onboarding path consistent with its credentials."""
        password_supplied = self.password is not None
        password_required = self.onboarding is UserOnboardingMode.PASSWORD_VERIFICATION
        if password_supplied != password_required:
            msg = "Password-verification onboarding requires exactly one password."
            raise ValueError(msg)
        return self


class UserUpdateCommand(BaseModel):
    """Typed set of user fields that one lifecycle mutation may change."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    email: UserEmail | None = None
    first_name: UserFirstName | None = None
    last_name: UserLastName | None = None
    is_active: bool | None = None
    role: OrganizationUserRole | None = None
    is_operator: bool | None = None
    email_verified: bool | None = None
    organization_id: int | None = None

    def changes(self) -> dict[str, object]:
        """Return only explicitly selected non-null lifecycle changes."""
        return cast("dict[str, object]", self.model_dump(exclude_none=True))
