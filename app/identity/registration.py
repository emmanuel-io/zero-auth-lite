"""Self-registration lifecycle for the canonical identity server."""

from sqlalchemy import insert
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm.attributes import set_committed_value

from app.db.models.organization import OrganizationDB
from app.db.models.organization_membership import OrganizationMembershipDB
from app.db.models.user import UserDB
from app.errors import ObjectAlreadyExistsError
from app.events.protocols import EventPublisher
from app.events.types import AccountVerificationRequested
from app.identity.dtos import RegisteredUserDTO, RegistrationCreateDTO
from app.identity.public_ids import format_organization_id, format_user_id
from app.identity.users.emails import (
    create_user_email,
    email_is_available,
)
from app.identity.users.enums import OrganizationUserRole, UserEmailStatus
from app.password.async_hashing import hash_password
from app.password.protocols import PasswordHasherProtocol
from app.public_ids import PublicId


class RegistrationService:
    """Create the first user and organization for a self-registration request."""

    def __init__(
        self,
        *,
        db_session: AsyncSession,
        event_publisher: EventPublisher,
        password_hasher: PasswordHasherProtocol,
    ) -> None:
        """Initialize registration lifecycle dependencies.

        Args:
            db_session: Request-scoped relational transaction.
            event_publisher: Transactional domain-event publisher.
            password_hasher: Application password-hashing provider.
        """
        self.db_session = db_session
        self.event_publisher = event_publisher
        self.password_hasher = password_hasher

    async def register(
        self, *, registration: RegistrationCreateDTO
    ) -> RegisteredUserDTO:
        """Create an organization and its initial administrator identity.

        Args:
            registration: Validated identity and organization data.

        Returns:
            Safe public representation of the registered identity.

        Raises:
            ObjectAlreadyExistsError: If the email is already owned or reserved.
        """
        password_hash = await hash_password(self.password_hasher, registration.password)
        if not await email_is_available(
            self.db_session,
            email=str(registration.email),
            excluding_user_id=None,
        ):
            raise ObjectAlreadyExistsError
        try:
            async with self.db_session.begin_nested():
                organization = (
                    await self.db_session.execute(
                        insert(OrganizationDB)
                        .values(name=registration.organization_name)
                        .returning(OrganizationDB)
                    )
                ).scalar_one()
                user = (
                    await self.db_session.execute(
                        insert(UserDB)
                        .values(
                            hashed_password=password_hash,
                            first_name=registration.first_name,
                            last_name=registration.last_name,
                            is_active=True,
                        )
                        .returning(UserDB)
                    )
                ).scalar_one()
                await self.db_session.execute(
                    insert(OrganizationMembershipDB).values(
                        user_id=user.id,
                        organization_id=organization.id,
                        role=OrganizationUserRole.ADMIN,
                    )
                )
                user_email = await create_user_email(
                    self.db_session,
                    user_id=user.id,
                    email=str(registration.email),
                    status=UserEmailStatus.CURRENT,
                )
                set_committed_value(user, "emails", [user_email])
                await self.db_session.flush()
        except IntegrityError as exc:
            raise ObjectAlreadyExistsError from exc

        registered = RegisteredUserDTO(
            id=format_user_id(PublicId(user.public_id)),
            organization_id=format_organization_id(PublicId(organization.public_id)),
            email=user.email,
            first_name=user.first_name,
            last_name=user.last_name,
            is_active=user.is_active,
            role=OrganizationUserRole.ADMIN,
            email_verified=user.email_verified,
        )
        await self.event_publisher.publish(
            AccountVerificationRequested(
                user_public_id=PublicId(user.public_id),
                user_email_id=user_email.id,
            )
        )
        return registered
