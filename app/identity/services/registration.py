"""Self-registration lifecycle for the canonical identity server."""

from sqlalchemy import insert
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.errors.common import ObjectAlreadyExistsError
from app.db.models.organization import OrganizationDB
from app.identity.dtos import RegisteredUserDTO, RegistrationCreateDTO
from app.identity.users.commands import UserCreateCommand, UserOnboardingMode
from app.identity.users.creation import create_user_identity
from app.identity.users.emails import (
    email_is_available,
    map_user_email_integrity_error,
)
from app.identity.users.enums import OrganizationMembershipRole
from app.notifications.events import AccountVerificationRequested
from app.notifications.protocols import NotificationPublisher
from app.password.async_hashing import hash_password
from app.password.protocols import PasswordHasherProtocol


class RegistrationService:
    """Create the first user and organization for a self-registration request."""

    def __init__(
        self,
        *,
        db_session: AsyncSession,
        notification_publisher: NotificationPublisher,
        password_hasher: PasswordHasherProtocol,
    ) -> None:
        """Initialize request persistence, notifications, and password hashing."""
        self.db_session = db_session
        self.notification_publisher = notification_publisher
        self.password_hasher = password_hasher

    async def register(
        self, *, registration: RegistrationCreateDTO
    ) -> RegisteredUserDTO:
        """Create an organization and its initial administrator identity.

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
                user, _membership, user_email = await create_user_identity(
                    self.db_session,
                    command=UserCreateCommand(
                        organization_id=organization.id,
                        email=registration.email,
                        onboarding=UserOnboardingMode.PASSWORD_VERIFICATION,
                        password=registration.password,
                        first_name=registration.first_name,
                        last_name=registration.last_name,
                        role=OrganizationMembershipRole.ADMIN,
                    ),
                    hashed_password=password_hash,
                )
        except IntegrityError as exc:
            raise map_user_email_integrity_error(exc) from exc

        registered = RegisteredUserDTO(
            public_id=user.public_id,
            organization_public_id=organization.public_id,
            email=user.email,
            first_name=user.first_name,
            last_name=user.last_name,
            is_active=user.is_active,
            role=OrganizationMembershipRole.ADMIN,
            email_verified=user.email_verified,
        )
        await self.notification_publisher.publish(
            AccountVerificationRequested(
                user_public_id=user.public_id,
                user_email_id=user_email.id,
            )
        )
        return registered
