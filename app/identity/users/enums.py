"""Organization-scoped user roles."""

from enum import StrEnum


class OrganizationUserRole(StrEnum):
    """Role held by a user inside one organization."""

    MEMBER = "member"
    ADMIN = "admin"


class UserEmailStatus(StrEnum):
    """Lifecycle state of one address owned by a user."""

    CURRENT = "current"
    PENDING = "pending"
    RETIRED = "retired"
