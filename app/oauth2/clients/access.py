"""OAuth2 client organization-access policy values."""

from enum import StrEnum
from typing import Final


class OAuth2ClientUserOrganizationAccess(StrEnum):
    """Control which organizations' users may use a global OAuth2 client."""

    UNRESTRICTED = "unrestricted"
    SINGLE = "single"
    SELECTED = "selected"


class OAuth2ClientMachineOrganizationAccess(StrEnum):
    """Control which organization resources a machine client may access."""

    NONE = "none"
    SINGLE = "single"
    SELECTED = "selected"
    UNRESTRICTED = "unrestricted"


OAUTH2_CLIENT_ORGANIZATION_ACCESS_LENGTH_MAX: Final[int] = max(
    *(len(value.value) for value in OAuth2ClientUserOrganizationAccess),
    *(len(value.value) for value in OAuth2ClientMachineOrganizationAccess),
)
