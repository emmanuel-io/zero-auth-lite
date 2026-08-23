"""Current-user profile and account self-service."""

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models.organization import OrganizationDB
from app.db.models.organization_membership import OrganizationMembershipDB
from app.db.models.user import UserDB
from app.errors import ObjectNotFoundError
from app.identity.organizations.dtos import OrganizationSelfReadDTO
from app.identity.services.lifecycle import UserLifecycleService
from app.identity.services.lifecycle_policy import EmailUpdatePolicy
from app.identity.users.commands import UserUpdateCommand
from app.identity.users.dtos import (
    to_user_self_read_dto,
    UserPasswordChangeDTO,
    UserSelfPatchDTO,
    UserSelfReadDTO,
)
from app.identity.users.emails import active_email_loader
from app.security.dtos import UserPrincipalContext


class UserSelfService:
    """Expose operations whose target is always the current user."""

    def __init__(
        self,
        *,
        db_session: AsyncSession,
        user_ctx: UserPrincipalContext,
        lifecycle: UserLifecycleService,
    ) -> None:
        """Initialize current-user operations."""
        self.db_session = db_session
        self.user_ctx = user_ctx
        self.lifecycle = lifecycle

    async def _read_target(self) -> tuple[UserDB, OrganizationMembershipDB]:
        """Read the current user by its internal identifier."""
        row = (
            await self.db_session.execute(
                select(UserDB, OrganizationMembershipDB)
                .options(active_email_loader())
                .join(
                    OrganizationMembershipDB,
                    OrganizationMembershipDB.user_id == UserDB.id,
                )
                .where(UserDB.id == self.user_ctx.user_id)
            )
        ).one_or_none()
        if row is None:
            raise ObjectNotFoundError
        return row[0], row[1]

    async def _read_with_organization(
        self,
    ) -> tuple[UserDB, OrganizationMembershipDB, OrganizationSelfReadDTO]:
        """Read the current user and its public organization data."""
        row = (
            await self.db_session.execute(
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
                .where(UserDB.id == self.user_ctx.user_id)
            )
        ).one_or_none()
        if row is None:
            raise ObjectNotFoundError
        user, membership, organization = row
        return (
            user,
            membership,
            OrganizationSelfReadDTO.model_validate(organization),
        )

    async def read(self) -> UserSelfReadDTO:
        """Read the current user's profile and organization."""
        user, membership, organization = await self._read_with_organization()
        return to_user_self_read_dto(user, organization, membership.role)

    async def patch(self, *, data: UserSelfPatchDTO) -> UserSelfReadDTO:
        """Patch fields managed directly by the current user."""
        command = UserUpdateCommand.model_validate(data.model_dump(exclude_unset=True))
        if not command.changes():
            return await self.read()
        target, membership, organization = await self._read_with_organization()
        row, membership = await self.lifecycle.update(
            target=target,
            membership=membership,
            command=command,
            email_policy=EmailUpdatePolicy.PENDING_VERIFICATION_ONLY,
        )
        return to_user_self_read_dto(row, organization, membership.role)

    async def change_password(self, *, data: UserPasswordChangeDTO) -> None:
        """Change the current user's password."""
        target, _membership = await self._read_target()
        await self.lifecycle.change_password_autonomously(target=target, data=data)

    async def delete(self) -> None:
        """Delete the current user's account."""
        target, membership = await self._read_target()
        await self.lifecycle.delete(targets=((target, membership),))
