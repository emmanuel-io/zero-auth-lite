"""Canonical permission definitions for route-level authorization."""

from enum import StrEnum

from app.enums import Role


class Permission(StrEnum):
    """Permission identifiers used by backend route dependencies."""

    PROFILE_READ = "profile:read"
    PROFILE_WRITE = "profile:write"
    ORGANIZATION_READ = "organization:read"
    ORGANIZATION_WRITE = "organization:write"
    ORGANIZATIONS_READ = "organizations:read"
    ORGANIZATIONS_WRITE = "organizations:write"
    USERS_READ = "users:read"
    USERS_WRITE = "users:write"
    OAUTH2_CLIENTS_READ = "oauth2_clients:read"
    OAUTH2_CLIENTS_WRITE = "oauth2_clients:write"


ORGANIZATION_USER_PERMISSIONS = frozenset(
    {
        Permission.PROFILE_READ,
        Permission.PROFILE_WRITE,
    }
)

ORGANIZATION_ADMIN_PERMISSIONS = frozenset(
    {
        *ORGANIZATION_USER_PERMISSIONS,
        Permission.ORGANIZATION_READ,
        Permission.ORGANIZATION_WRITE,
    }
)

OPERATOR_PERMISSIONS = frozenset(
    {
        *ORGANIZATION_USER_PERMISSIONS,
        Permission.ORGANIZATIONS_READ,
        Permission.ORGANIZATIONS_WRITE,
        Permission.USERS_READ,
        Permission.USERS_WRITE,
        Permission.OAUTH2_CLIENTS_READ,
        Permission.OAUTH2_CLIENTS_WRITE,
    }
)

PERMISSION_DESCRIPTIONS: dict[Permission, str] = {
    Permission.PROFILE_READ: "Read the authenticated user's profile.",
    Permission.PROFILE_WRITE: "Update the authenticated user's profile.",
    Permission.ORGANIZATION_READ: (
        "Read resources in the current organization administration API."
    ),
    Permission.ORGANIZATION_WRITE: (
        "Change resources in the current organization administration API."
    ),
    Permission.ORGANIZATIONS_READ: (
        "Read organizations through the server-operator API."
    ),
    Permission.ORGANIZATIONS_WRITE: (
        "Change organizations through the server-operator API."
    ),
    Permission.USERS_READ: "Read users through the server-operator API.",
    Permission.USERS_WRITE: "Change users through the server-operator API.",
    Permission.OAUTH2_CLIENTS_READ: (
        "Read OAuth2 clients through the server-operator API."
    ),
    Permission.OAUTH2_CLIENTS_WRITE: (
        "Change OAuth2 clients through the server-operator API."
    ),
}


def permissions_for_roles(roles: frozenset[Role | str]) -> frozenset[Permission]:
    """Return the canonical permissions granted by role membership."""
    normalized_roles = frozenset(Role(role) for role in roles)
    permissions = set(ORGANIZATION_USER_PERMISSIONS)
    if Role.ORGANIZATION_ADMIN in normalized_roles:
        permissions.update(ORGANIZATION_ADMIN_PERMISSIONS)
    if Role.OPERATOR in normalized_roles:
        permissions.update(OPERATOR_PERMISSIONS)
    return frozenset(permissions)
