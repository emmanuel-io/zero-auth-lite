"""Organization membership roles and user lifecycle states."""

from enum import StrEnum


class EmailUpdatePolicy(StrEnum):
    """Define how a changed user email enters the verification workflow."""

    PENDING_VERIFICATION_ONLY = "pending_verification_only"
    DIRECT_IF_UNVERIFIED = "direct_if_unverified"


class OrganizationMembershipRole(StrEnum):
    """Role held by a user inside one organization."""

    MEMBER = "member"
    ADMIN = "admin"


class UserEmailStatus(StrEnum):
    """Lifecycle state of one address owned by a user."""

    CURRENT = "current"
    PENDING = "pending"
    RETIRED = "retired"
