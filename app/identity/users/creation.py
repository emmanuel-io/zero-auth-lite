"""Persistence for creating one user identity and its required records."""

from datetime import datetime, UTC

from sqlalchemy import insert
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm.attributes import set_committed_value

from app.db.models.organization_membership import OrganizationMembershipDB
from app.db.models.user import UserDB, UserEmailDB
from app.identity.users.commands import UserCreateCommand, UserOnboardingMode
from app.identity.users.emails import normalize_email
from app.identity.users.enums import UserEmailStatus


async def create_user_identity(
    db_session: AsyncSession,
    *,
    command: UserCreateCommand,
    hashed_password: str,
) -> tuple[UserDB, OrganizationMembershipDB, UserEmailDB]:
    """Persist the identity's required rows without owning the transaction."""
    user_values = command.model_dump(
        exclude={
            "email",
            "email_verified",
            "onboarding",
            "organization_id",
            "password",
            "role",
        }
    )
    user_values["hashed_password"] = hashed_password
    user_values["invitation_pending"] = (
        command.onboarding is UserOnboardingMode.INVITATION
    )
    user = (
        await db_session.execute(insert(UserDB).values(**user_values).returning(UserDB))
    ).scalar_one()
    membership = (
        await db_session.execute(
            insert(OrganizationMembershipDB)
            .values(
                user_id=user.id,
                organization_id=command.organization_id,
                role=command.role,
            )
            .returning(OrganizationMembershipDB)
        )
    ).scalar_one()
    display_email = str(command.email).strip()
    user_email = (
        await db_session.execute(
            insert(UserEmailDB)
            .values(
                user_id=user.id,
                email=display_email,
                normalized_email=normalize_email(display_email),
                status=UserEmailStatus.CURRENT,
                verified_at=datetime.now(UTC) if command.email_verified else None,
            )
            .returning(UserEmailDB)
        )
    ).scalar_one()
    set_committed_value(user, "emails", [user_email])
    await db_session.flush()
    return user, membership, user_email
