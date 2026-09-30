"""Application authentication and authorization principal contexts."""

from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum
from typing import Protocol
from uuid import UUID

from app.security.permissions import Permission, permissions_for_roles
from app.security.roles import Role


class AuthenticationMechanism(StrEnum):
    """Credential mechanism used to authenticate a principal."""

    BROWSER_SESSION = "browser_session"
    OAUTH2_BEARER = "oauth2_bearer"


class PrincipalContext(Protocol):
    """Common read-only facts exposed by every authenticated actor."""

    @property
    def organization_id(self) -> int | None:
        """Return the actor's organization when one is bound."""
        ...

    @property
    def authentication_mechanism(self) -> AuthenticationMechanism:
        """Return the credential mechanism used for authentication."""
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
    def user_public_id(self) -> UUID:
        """Return the public user identifier."""
        ...

    @property
    def organization_public_id(self) -> UUID:
        """Return the public organization identifier."""
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
    def client_id(self) -> UUID | None:
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
    raw_session_id: str
    user_public_id: UUID
    organization_public_id: UUID
    email: str = ""
    first_name: str = ""
    last_name: str = ""
    organization_name: str = ""
    roles: frozenset[Role] = field(default_factory=frozenset)
    permissions: frozenset[Permission] = field(default_factory=frozenset, init=False)
    scopes: frozenset[str] = field(default_factory=frozenset, init=False)
    authenticated_at: datetime | None = None
    authentication_mechanism: AuthenticationMechanism = field(
        default=AuthenticationMechanism.BROWSER_SESSION,
        init=False,
    )
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
    def display_name(self) -> str:
        """Return the human-readable name shown in browser navigation."""
        name = " ".join(part for part in (self.first_name, self.last_name) if part)
        return name or self.email

    @property
    def is_operator(self) -> bool:
        """Return whether the user manages the control plane."""
        return Role.OPERATOR in self.roles


@dataclass(frozen=True, slots=True)
class OAuth2UserPrincipalContext:
    """Authenticated user backed by an OAuth2 token family."""

    user_id: int
    organization_id: int
    oauth2_session_id: int
    client_id: UUID
    user_public_id: UUID
    organization_public_id: UUID
    scopes: frozenset[str] = field(default_factory=frozenset)
    roles: frozenset[Role] = field(default_factory=frozenset)
    permissions: frozenset[Permission] = field(default_factory=frozenset, init=False)
    authentication_mechanism: AuthenticationMechanism = field(
        default=AuthenticationMechanism.OAUTH2_BEARER,
        init=False,
    )

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
    oauth2_session_id: int
    client_id: UUID
    scopes: frozenset[str] = field(default_factory=frozenset)
    authentication_mechanism: AuthenticationMechanism = field(
        default=AuthenticationMechanism.OAUTH2_BEARER,
        init=False,
    )

    def __post_init__(self) -> None:
        """Normalize bearer scopes."""
        object.__setattr__(self, "scopes", frozenset(self.scopes))


type OAuth2PrincipalContext = OAuth2UserPrincipalContext | OAuth2ClientPrincipalContext
type AuthenticatedPrincipalContext = (
    BrowserUserPrincipalContext
    | OAuth2UserPrincipalContext
    | OAuth2ClientPrincipalContext
)
