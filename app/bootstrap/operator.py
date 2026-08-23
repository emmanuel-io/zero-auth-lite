"""First-run bootstrap for the initial organization and operator."""

from datetime import datetime, UTC
from logging import getLogger

from sqlalchemy import func, insert, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm.attributes import set_committed_value

from app.bootstrap.settings import BootstrapSettings
from app.db.models.organization import OrganizationDB
from app.db.models.organization_membership import OrganizationMembershipDB
from app.db.models.user import UserDB
from app.identity.public_ids import format_organization_id
from app.identity.users.emails import create_user_email
from app.identity.users.enums import OrganizationUserRole, UserEmailStatus
from app.password.async_hashing import hash_password
from app.password.protocols import PasswordHasherProtocol
from app.password.validation import validate_password


logger = getLogger(__name__)


async def bootstrap_operator_user(
    *,
    db_session: AsyncSession,
    settings: BootstrapSettings,
    password_hasher: PasswordHasherProtocol,
) -> None:
    """Create the first organization and operator when the user table is empty.

    Raises:
        ValueError: If bootstrap is partially configured.
    """
    if settings.operator_email is None and settings.operator_password is None:
        return
    if settings.operator_email is None or settings.operator_password is None:
        msg = (
            "Bootstrap operator requires both bootstrap__operator_email and "
            "bootstrap__operator_password."
        )
        raise ValueError(msg)

    existing_users = await _count_users(db_session=db_session)
    if existing_users > 0:
        logger.info("Skipping bootstrap operator because users already exist.")
        return
    # Do not retain the startup read transaction while computing Argon2.
    await db_session.commit()

    password = settings.operator_password.get_secret_value()
    validate_password(password)
    password_hash = await hash_password(password_hasher, password)

    organization = (
        await db_session.execute(
            insert(OrganizationDB)
            .values(name=settings.organization_name)
            .returning(OrganizationDB)
        )
    ).scalar_one()

    user = (
        await db_session.execute(
            insert(UserDB)
            .values(
                first_name=settings.first_name,
                last_name=settings.last_name,
                hashed_password=password_hash,
                is_active=True,
                is_operator=True,
            )
            .returning(UserDB)
        )
    ).scalar_one()
    await db_session.execute(
        insert(OrganizationMembershipDB).values(
            user_id=user.id,
            organization_id=organization.id,
            role=OrganizationUserRole.ADMIN,
        )
    )
    user_email = await create_user_email(
        db_session,
        user_id=user.id,
        email=str(settings.operator_email),
        status=UserEmailStatus.CURRENT,
        verified_at=datetime.now(UTC),
    )
    set_committed_value(user, "emails", [user_email])
    await db_session.commit()
    logger.warning(
        "event=bootstrap_operator_created outcome=success "
        "reason=first_user_bootstrap organization_id=%s "
        "action=remove_bootstrap_credentials",
        format_organization_id(organization.public_id),
    )


async def _count_users(*, db_session: AsyncSession) -> int:
    """Return the number of canonical users."""
    return int(
        (
            await db_session.execute(select(func.count()).select_from(UserDB))
        ).scalar_one()
    )
