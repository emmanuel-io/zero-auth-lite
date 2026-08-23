"""Application authentication and authorization principal contexts."""

from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum
from typing import Protocol

from app.enums import Role
from app.oauth2.clients.access import OAuth2ClientMachineOrganizationAccess
from app.public_ids import PublicId
from app.security.permissions import Permission, permissions_for_roles


class AuthMethod(StrEnum):
    """Authentication method used to resolve a principal."""

    SESSION = "session"
    OAUTH2 = "oauth2"


class PrincipalContext(Protocol):
    """Common read-only facts exposed by every authenticated actor."""

    @property
    def organization_id(self) -> int | None:
        """Return the actor's organization when one is bound."""
        ...

    @property
    def session_id(self) -> str | int:
        """Return the authority-bearing session identifier."""
        ...

    @property
    def auth_method(self) -> AuthMethod:
        """Return the authentication transport."""
        ...


class UserPrincipalContext(PrincipalContext, Protocol):
    """Read-only identity and authorization facts for a user principal."""

    @property
    def user_id(self) -> int:
        """Return the internal user identifier."""
        ...

    @property
    def organization_id(self) -> int:
        """Return the internal organization identifier."""
        ...

    @property
    def user_public_id(self) -> PublicId | None:
        """Return the public user identifier when loaded."""
        ...

    @property
    def organization_public_id(self) -> PublicId | None:
        """Return the public organization identifier when loaded."""
        ...

    @property
    def roles(self) -> frozenset[Role]:
        """Return normalized user roles."""
        ...

    @property
    def permissions(self) -> frozenset[Permission]:
        """Return canonical user permissions."""
        ...

    @property
    def scopes(self) -> frozenset[str]:
        """Return bearer scopes, or an empty set for browser sessions."""
        ...

    @property
    def client_id(self) -> str | None:
        """Return the issuing OAuth2 client for a bearer user, when present."""
        ...

    @property
    def has_administrative_role(self) -> bool:
        """Return whether the user has an administrative role."""
        ...

    @property
    def is_operator(self) -> bool:
        """Return whether the user manages the control plane."""
        ...


class InteractiveUserPrincipalContext(UserPrincipalContext, Protocol):
    """User principal carrying the time of an interactive authentication."""

    @property
    def authenticated_at(self) -> datetime | None:
        """Return the original user-authentication time when known."""
        ...


def _normalize_user_authority(
    *, roles: frozenset[Role | str]
) -> tuple[frozenset[Role], frozenset[Permission]]:
    """Normalize user roles and derive their canonical permissions."""
    normalized_roles = frozenset(Role(role) for role in roles)
    return normalized_roles, permissions_for_roles(normalized_roles)


@dataclass(frozen=True, slots=True)
class BrowserUserPrincipalContext:
    """Authenticated browser user backed by one raw session cookie value."""

    user_id: int
    organization_id: int
    session_id: str
    user_public_id: PublicId | None = None
    organization_public_id: PublicId | None = None
    roles: frozenset[Role] = field(default_factory=frozenset)
    permissions: frozenset[Permission] = field(default_factory=frozenset, init=False)
    scopes: frozenset[str] = field(default_factory=frozenset, init=False)
    authenticated_at: datetime | None = None
    auth_method: AuthMethod = field(default=AuthMethod.SESSION, init=False)
    client_id: None = field(default=None, init=False)

    def __post_init__(self) -> None:
        """Normalize role-derived browser authority."""
        roles, permissions = _normalize_user_authority(roles=self.roles)
        object.__setattr__(self, "roles", roles)
        object.__setattr__(self, "permissions", permissions)

    @property
    def has_administrative_role(self) -> bool:
        """Return whether the user has either administrative role."""
        return Role.ORGANIZATION_ADMIN in self.roles or self.is_operator

    @property
    def is_operator(self) -> bool:
        """Return whether the user manages the control plane."""
        return Role.OPERATOR in self.roles


@dataclass(frozen=True, slots=True)
class OAuth2UserPrincipalContext:
    """Authenticated user backed by an OAuth2 token family."""

    user_id: int
    organization_id: int
    session_id: int
    client_id: str
    scopes: frozenset[str] = field(default_factory=frozenset)
    user_public_id: PublicId | None = None
    organization_public_id: PublicId | None = None
    roles: frozenset[Role] = field(default_factory=frozenset)
    permissions: frozenset[Permission] = field(default_factory=frozenset, init=False)
    auth_method: AuthMethod = field(default=AuthMethod.OAUTH2, init=False)

    def __post_init__(self) -> None:
        """Normalize bearer scopes and role-derived user authority."""
        roles, role_permissions = _normalize_user_authority(roles=self.roles)
        permissions = frozenset(
            permission
            for permission in role_permissions
            if permission.value in self.scopes
        )
        object.__setattr__(self, "roles", roles)
        object.__setattr__(self, "permissions", permissions)
        object.__setattr__(self, "scopes", frozenset(self.scopes))

    @property
    def has_administrative_role(self) -> bool:
        """Return whether the user has either administrative role."""
        return Role.ORGANIZATION_ADMIN in self.roles or self.is_operator

    @property
    def is_operator(self) -> bool:
        """Return whether the user manages the control plane."""
        return Role.OPERATOR in self.roles


@dataclass(frozen=True, slots=True)
class OAuth2ClientPrincipalContext:
    """Authenticated machine client backed by an OAuth2 token family."""

    organization_id: int | None
    session_id: int
    client_id: str
    machine_organization_access: OAuth2ClientMachineOrganizationAccess
    scopes: frozenset[str] = field(default_factory=frozenset)
    auth_method: AuthMethod = field(default=AuthMethod.OAUTH2, init=False)

    def __post_init__(self) -> None:
        """Normalize bearer scopes."""
        object.__setattr__(self, "scopes", frozenset(self.scopes))


type OAuth2PrincipalContext = OAuth2UserPrincipalContext | OAuth2ClientPrincipalContext
type AuthenticatedPrincipalContext = (
    BrowserUserPrincipalContext
    | OAuth2UserPrincipalContext
    | OAuth2ClientPrincipalContext
)
