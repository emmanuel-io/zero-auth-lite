"""Organization service data transfer objects."""

from uuid import UUID

from pydantic import BaseModel, ConfigDict

from app.identity.organizations.types import OrganizationName


class _OrganizationBase(BaseModel):
    """Shared organization service data."""

    model_config = ConfigDict(extra="forbid")

    name: OrganizationName


class OrganizationCreateDTO(_OrganizationBase):
    """Organization creation service input."""


class OrganizationReadDTO(_OrganizationBase):
    """Organization service output."""

    model_config = ConfigDict(from_attributes=True)

    public_id: UUID


class OrganizationSelfReadDTO(_OrganizationBase):
    """Organization metadata embedded in the current-user profile."""

    model_config = ConfigDict(from_attributes=True)


class OrganizationUpdateDTO(_OrganizationBase):
    """Organization update service input."""
