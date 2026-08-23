"""Settings for first-run operator bootstrap."""

from pydantic import BaseModel, ConfigDict, Field, SecretStr

from app.identity.organizations.types import OrganizationName
from app.identity.users.types import UserEmail, UserFirstName, UserLastName


class BootstrapSettings(BaseModel):
    """First-run operator bootstrap settings."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    operator_email: UserEmail | None = Field(
        default=None,
        description="Email for the first bootstrap operator.",
    )
    operator_password: SecretStr | None = Field(
        default=None,
        description="Password for the first bootstrap operator.",
    )
    organization_name: OrganizationName = Field(
        default="Zero Auth Lite",
        description="Organization name created for the bootstrap operator.",
    )
    first_name: UserFirstName = Field(
        default="Bootstrap",
        description="First name for the bootstrap operator.",
    )
    last_name: UserLastName = Field(
        default="Operator",
        description="Last name for the bootstrap operator.",
    )
