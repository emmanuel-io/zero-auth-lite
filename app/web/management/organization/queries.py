"""Query fields for organization management browser lists."""

from datetime import date
from typing import Self

from pydantic import BaseModel, ConfigDict, Field, model_validator, UUID4

from app.identity.users.enums import OrganizationMembershipRole
from app.identity.users.specs import UserSpecs
from app.oauth2.grants.types import OAuth2SessionGrantType
from app.web.management.errors import ManagementStartDateAfterEndDateError


class OrganizationUserFilters(BaseModel):
    """User search fields independent of pagination and page notices."""

    model_config = ConfigDict(extra="ignore")

    q: str | None = Field(default=None, max_length=UserSpecs.SEARCH_QUERY_LENGTH_MAX)
    role: OrganizationMembershipRole | None = None
    active: bool | None = None
    email_verified: bool | None = None
    created_from: date | None = None
    created_to: date | None = None

    @model_validator(mode="after")
    def validate_created_range(self) -> Self:
        """Preserve the browser error for a reversed creation-date range."""
        if (
            self.created_from is not None
            and self.created_to is not None
            and self.created_from > self.created_to
        ):
            raise ManagementStartDateAfterEndDateError
        return self


class OrganizationOAuth2SessionFilters(BaseModel):
    """Session filters for the organization management page."""

    model_config = ConfigDict(extra="ignore")

    client_id: UUID4 | None = None
    grant_type: OAuth2SessionGrantType | None = None
    user_id: UUID4 | None = None
    active_only: bool = True
