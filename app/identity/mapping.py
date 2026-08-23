"""Pure ORM-to-DTO mapping for canonical identities."""

from sqlalchemy.engine import Row

from app.core.time import as_utc_aware
from app.db.models.organization import OrganizationDB
from app.db.models.organization_membership import OrganizationMembershipDB
from app.db.models.user import UserDB
from app.enums import Role
from app.identity.dtos import IdentityDTO, IdentityOrganizationDTO, IdentityUserDTO
from app.identity.users.enums import OrganizationUserRole
from app.public_ids import PublicId


def to_identity(
    row: Row[tuple[UserDB, OrganizationMembershipDB, OrganizationDB]],
) -> IdentityDTO:
    """Convert one joined user, role, and organization row to an identity."""
    user, membership, organization = row
    roles: list[str] = []
    if membership.role is OrganizationUserRole.ADMIN:
        roles.append(Role.ORGANIZATION_ADMIN.value)
    if user.is_operator:
        roles.append(Role.OPERATOR.value)
    invalid_before = user.sessions_invalid_before
    if invalid_before is not None:
        invalid_before = as_utc_aware(invalid_before)
    return IdentityDTO(
        user=IdentityUserDTO(
            id=user.id,
            public_id=PublicId(user.public_id),
            organization_id=membership.organization_id,
            organization_public_id=PublicId(organization.public_id),
            email=user.email,
            hashed_password=user.hashed_password,
            first_name=user.first_name,
            last_name=user.last_name,
            pending_email=user.pending_email,
            is_active=user.is_active,
            email_verified=user.email_verified,
            roles=tuple(roles),
            sessions_invalid_before=invalid_before,
        ),
        organization=to_organization(organization),
    )


def to_organization(organization: OrganizationDB) -> IdentityOrganizationDTO:
    """Convert an organization ORM row to the stable identity DTO."""
    return IdentityOrganizationDTO(
        id=organization.id,
        public_id=PublicId(organization.public_id),
        name=organization.name,
    )
