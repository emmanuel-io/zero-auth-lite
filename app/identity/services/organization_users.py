"""Organization-scoped user service."""

from uuid import UUID

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.sql import Select

from app.core.errors.common import ForbiddenOperationError, ObjectNotFoundError
from app.db.models.organization_membership import OrganizationMembershipDB
from app.db.models.user import UserDB, UserEmailDB
from app.identity.services.lifecycle import UserLifecycleService
from app.identity.users.commands import (
    UserCreateCommand,
    UserOnboardingMode,
    UserUpdateCommand,
)
from app.identity.users.criteria import (
    OrganizationUserSearchCriteriaDTO,
    UserPageDTO,
)
from app.identity.users.dtos import (
    OrganizationUserCreateDTO,
    OrganizationUserPatchDTO,
    OrganizationUserReadDTO,
    OrganizationUserReplaceDTO,
    to_organization_user_read_dto,
    UserSessionTargetDTO,
)
from app.identity.users.emails import active_email_loader
from app.identity.users.enums import EmailUpdatePolicy, UserEmailStatus
from app.identity.users.search import (
    apply_user_search_sort,
    join_user_search_emails,
    user_search_filters,
)
from app.security.principals import UserPrincipalContext
from app.security.roles import Role


class OrganizationUsersService:
    """Manage users in the authenticated user's organization."""

    def __init__(
        self,
        *,
        db_session: AsyncSession,
        actor_ctx: UserPrincipalContext,
        lifecycle: UserLifecycleService,
    ) -> None:
        """Initialize organization-scoped administration."""
        self.db_session = db_session
        self.actor_ctx = actor_ctx
        self.lifecycle = lifecycle

    def _require_actor(self) -> None:
        """Require an explicit organization-administrator role."""
        if Role.ORGANIZATION_ADMIN not in self.actor_ctx.roles:
            raise ForbiddenOperationError

    @staticmethod
    def _require_managed_target(*, target_is_operator: bool) -> None:
        """Keep operator accounts outside organization-scoped mutations."""
        if target_is_operator:
            raise ForbiddenOperationError

    async def _target(
        self, *, user_id: UUID
    ) -> tuple[UserDB, OrganizationMembershipDB]:
        """Resolve a target constrained to the actor's organization."""
        self._require_actor()
        target = (
            await self.db_session.execute(
                select(UserDB, OrganizationMembershipDB)
                .options(active_email_loader())
                .join(
                    OrganizationMembershipDB,
                    OrganizationMembershipDB.user_id == UserDB.id,
                )
                .where(UserDB.public_id == user_id)
                .where(
                    OrganizationMembershipDB.organization_id
                    == self.actor_ctx.organization_id
                )
            )
        ).one_or_none()
        if target is None:
            raise ObjectNotFoundError
        return target[0], target[1]

    def _search_statement(
        self, *, criteria: OrganizationUserSearchCriteriaDTO
    ) -> Select[tuple[UserDB, OrganizationMembershipDB]]:
        """Build an organization-scoped user search statement."""
        statement = join_user_search_emails(
            select(UserDB, OrganizationMembershipDB)
            .options(active_email_loader())
            .join(
                OrganizationMembershipDB,
                OrganizationMembershipDB.user_id == UserDB.id,
            )
        )
        return statement.where(
            OrganizationMembershipDB.organization_id == self.actor_ctx.organization_id,
            *user_search_filters(criteria=criteria),
        )

    async def search(
        self, *, criteria: OrganizationUserSearchCriteriaDTO
    ) -> UserPageDTO[OrganizationUserReadDTO]:
        """Search users in the actor's organization."""
        self._require_actor()
        statement = self._search_statement(criteria=criteria)
        rows = (
            await self.db_session.execute(
                apply_user_search_sort(statement, sort=criteria.sort)
                .offset(criteria.offset)
                .limit(criteria.limit)
            )
        ).all()
        total = int(
            (
                await self.db_session.execute(
                    statement.with_only_columns(
                        func.count(), maintain_column_froms=True
                    ).order_by(None)
                )
            ).scalar_one()
        )
        return UserPageDTO(
            items=[
                to_organization_user_read_dto(user, membership.role)
                for user, membership in rows
            ],
            total=total,
        )

    async def get(self, *, user_id: UUID) -> OrganizationUserReadDTO:
        """Read one user in the actor's organization."""
        user, membership = await self._target(user_id=user_id)
        return to_organization_user_read_dto(user, membership.role)

    async def get_session_target(self, *, user_id: UUID) -> UserSessionTargetDTO:
        """Return a minimal organization-authorized session target in one query."""
        self._require_actor()
        target = (
            await self.db_session.execute(
                select(UserDB.id, UserDB.is_operator, UserEmailDB.email)
                .join(
                    OrganizationMembershipDB,
                    OrganizationMembershipDB.user_id == UserDB.id,
                )
                .join(UserEmailDB, UserEmailDB.user_id == UserDB.id)
                .where(UserDB.public_id == user_id)
                .where(
                    OrganizationMembershipDB.organization_id
                    == self.actor_ctx.organization_id
                )
                .where(UserEmailDB.status == UserEmailStatus.CURRENT)
            )
        ).one_or_none()
        if target is None:
            raise ObjectNotFoundError
        internal_user_id, is_operator, email = target
        self._require_managed_target(target_is_operator=is_operator)
        return UserSessionTargetDTO(
            internal_user_id=internal_user_id,
            email=email,
        )

    async def create(
        self, *, dto: OrganizationUserCreateDTO
    ) -> OrganizationUserReadDTO:
        """Create or invite a user in the actor's organization."""
        self._require_actor()
        row, membership = await self.lifecycle.create(
            command=UserCreateCommand(
                organization_id=self.actor_ctx.organization_id,
                onboarding=(
                    UserOnboardingMode.PASSWORD_VERIFICATION
                    if dto.password is not None
                    else UserOnboardingMode.INVITATION
                ),
                **dto.model_dump(),
            ),
        )
        return to_organization_user_read_dto(row, membership.role)

    async def resend_invitation(self, *, user_id: UUID) -> None:
        """Resend an invitation to an organization user."""
        target, _membership = await self._target(user_id=user_id)
        self._require_managed_target(target_is_operator=target.is_operator)
        await self.lifecycle.resend_invitation(target=target)

    async def patch(
        self, *, user_id: UUID, dto: OrganizationUserPatchDTO
    ) -> OrganizationUserReadDTO:
        """Patch an organization-managed user representation."""
        command = UserUpdateCommand.model_validate(dto.model_dump(exclude_unset=True))
        if not command.changes():
            return await self.get(user_id=user_id)
        target, membership = await self._target(user_id=user_id)
        self._require_managed_target(target_is_operator=target.is_operator)
        row, membership = await self.lifecycle.update(
            target=target,
            membership=membership,
            command=command,
            email_policy=EmailUpdatePolicy.DIRECT_IF_UNVERIFIED,
        )
        return to_organization_user_read_dto(row, membership.role)

    async def replace(
        self, *, user_id: UUID, dto: OrganizationUserReplaceDTO
    ) -> OrganizationUserReadDTO:
        """Replace an organization-managed user representation."""
        target, membership = await self._target(user_id=user_id)
        self._require_managed_target(target_is_operator=target.is_operator)
        row, membership = await self.lifecycle.update(
            target=target,
            membership=membership,
            command=UserUpdateCommand.model_validate(dto.model_dump()),
            email_policy=EmailUpdatePolicy.DIRECT_IF_UNVERIFIED,
        )
        return to_organization_user_read_dto(row, membership.role)

    async def delete(self, *, user_id: UUID) -> None:
        """Delete a user from the actor's organization."""
        target, membership = await self._target(user_id=user_id)
        self._require_managed_target(target_is_operator=target.is_operator)
        await self.lifecycle.delete(targets=((target, membership),))
