"""Query fields for operator management browser lists."""

from pydantic import BaseModel, ConfigDict, Field, UUID4

from app.identity.users.enums import OrganizationMembershipRole
from app.identity.users.specs import UserSpecs


class ServerUserFilters(BaseModel):
    """User filters independent of pagination and page notices."""

    model_config = ConfigDict(extra="ignore")

    q: str | None = Field(default=None, max_length=UserSpecs.SEARCH_QUERY_LENGTH_MAX)
    organization_id: UUID4 | None = None
    role: OrganizationMembershipRole | None = None
    operator: bool | None = None
    active: bool | None = None
    email_verified: bool | None = None
