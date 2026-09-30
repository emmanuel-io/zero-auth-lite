"""Typed template models for organization administration."""

from dataclasses import dataclass
from datetime import datetime

from app.identity.users.dtos import OrganizationUserReadDTO
from app.identity.users.enums import OrganizationMembershipRole
from app.oauth2.grants.types import OAuth2SessionGrantType
from app.oauth2.organization_oauth2_sessions.dtos import OrganizationOAuth2SessionDTO


@dataclass(frozen=True, slots=True)
class OrganizationUserView:
    """User fields rendered by organization templates."""

    id: str
    email: str
    pending_email: str | None
    first_name: str
    last_name: str
    is_active: bool
    role: OrganizationMembershipRole
    email_verified: bool
    session_management_allowed: bool
    created_at: datetime

    @classmethod
    def from_dto(cls, user: OrganizationUserReadDTO) -> "OrganizationUserView":
        """Build a template model from the service DTO."""
        return cls(
            id=str(user.public_id),
            email=str(user.email),
            pending_email=str(user.pending_email) if user.pending_email else None,
            first_name=user.first_name,
            last_name=user.last_name,
            is_active=user.is_active,
            role=user.role,
            email_verified=user.email_verified,
            session_management_allowed=user.session_management_allowed,
            created_at=user.created_at,
        )


@dataclass(frozen=True, slots=True)
class OrganizationOAuth2SessionView:
    """OAuth2 session fields rendered by organization templates."""

    id: str
    client_id: str
    grant_type: OAuth2SessionGrantType
    scopes: list[str]
    user_id: str | None
    active: bool
    created_at: datetime

    @classmethod
    def from_dto(
        cls, item: OrganizationOAuth2SessionDTO
    ) -> "OrganizationOAuth2SessionView":
        """Build a template model from the service DTO."""
        return cls(
            id=str(item.public_id),
            client_id=str(item.client_id),
            grant_type=item.grant_type,
            scopes=item.scopes,
            user_id=str(item.user_public_id)
            if item.user_public_id is not None
            else None,
            active=item.active,
            created_at=item.created_at,
        )
