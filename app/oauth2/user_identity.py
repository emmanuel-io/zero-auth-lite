"""OAuth2 eligibility checks for user-backed identities."""

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models.organization import OrganizationDB
from app.db.models.organization_membership import OrganizationMembershipDB
from app.db.models.user import UserDB
from app.identity.dtos import IdentityDTO
from app.identity.mapping import to_identity
from app.identity.users.emails import active_email_loader


async def load_eligible_oauth2_user_identity(
    *,
    db_session: AsyncSession,
    user_id: int | None,
    organization_id: int | None,
) -> IdentityDTO | None:
    """Load an active verified user in the expected organization."""
    if user_id is None or organization_id is None:
        return None
    row = (
        await db_session.execute(
            select(UserDB, OrganizationMembershipDB, OrganizationDB)
            .options(active_email_loader())
            .join(
                OrganizationMembershipDB,
                OrganizationMembershipDB.user_id == UserDB.id,
            )
            .join(
                OrganizationDB,
                OrganizationDB.id == OrganizationMembershipDB.organization_id,
            )
            .where(UserDB.id == user_id)
        )
    ).one_or_none()
    identity = to_identity(row) if row is not None else None
    if identity is None or identity.organization.id != organization_id:
        return None
    if not identity.user.is_active or not identity.user.email_verified:
        return None
    return identity
