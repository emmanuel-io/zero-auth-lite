"""Organization-scoped user service."""

from sqlalchemy import and_, func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import aliased
from sqlalchemy.sql import Select

from app.db.models.organization_membership import OrganizationMembershipDB
from app.db.models.user import UserDB, UserEmailDB
from app.enums import Role
from app.errors import ForbiddenOperationError, ObjectNotFoundError
from app.identity.services.lifecycle import UserLifecycleService
from app.identity.services.lifecycle_policy import EmailUpdatePolicy
from app.identity.users.authorization import require_organization_managed_target
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
)
from app.identity.users.emails import active_email_loader
from app.identity.users.enums import UserEmailStatus
from app.identity.users.query import (
    boolean_state_filter,
    compact_filters,
    created_window_filter,
    parse_sort,
    search_filter,
)
from app.public_ids import PublicId
from app.security.dtos import UserPrincipalContext


CurrentEmail = aliased(UserEmailDB, name="current_email")
PendingEmail = aliased(UserEmailDB, name="pending_email")


class OrganizationUsersService:
    """Manage users in the authenticated user's organization."""

    def __init__(
        self,
        *,
        db_session: AsyncSession,
        user_ctx: UserPrincipalContext,
        lifecycle: UserLifecycleService,
    ) -> None:
        """Initialize organization-scoped administration."""
        self.db_session = db_session
        self.actor_ctx = user_ctx
        self.lifecycle = lifecycle

    def _require_actor(self) -> None:
        """Require an explicit organization-administrator role."""
        if Role.ORGANIZATION_ADMIN not in self.actor_ctx.roles:
            raise ForbiddenOperationError

    async def _target(
        self, *, user_id: PublicId
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
        statement = (
            select(UserDB, OrganizationMembershipDB)
            .options(active_email_loader())
            .join(
                OrganizationMembershipDB,
                OrganizationMembershipDB.user_id == UserDB.id,
            )
            .join(
                CurrentEmail,
                and_(
                    CurrentEmail.user_id == UserDB.id,
                    CurrentEmail.status == UserEmailStatus.CURRENT,
                ),
            )
            .outerjoin(
                PendingEmail,
                and_(
                    PendingEmail.user_id == UserDB.id,
                    PendingEmail.status == UserEmailStatus.PENDING,
                ),
            )
            .where(
                OrganizationMembershipDB.organization_id
                == self.actor_ctx.organization_id
            )
        )
        return statement.where(
            *compact_filters(
                search_filter(
                    q=criteria.q,
                    columns=(
                        CurrentEmail.email,
                        PendingEmail.email,
                        UserDB.first_name,
                        UserDB.last_name,
                    ),
                ),
                OrganizationMembershipDB.role == criteria.role
                if criteria.role is not None
                else None,
                boolean_state_filter(UserDB.is_active, value=criteria.active),
                (
                    CurrentEmail.verified_at.is_not(None)
                    if criteria.email_verified is True
                    else CurrentEmail.verified_at.is_(None)
                    if criteria.email_verified is False
                    else None
                ),
                created_window_filter(
                    column=UserDB.created_at,
                    created_from=criteria.created_from,
                    created_to=criteria.created_to,
                ),
            )
        )

    @staticmethod
    def _apply_sort(
        statement: Select[tuple[UserDB, OrganizationMembershipDB]], *, sort: str | None
    ) -> Select[tuple[UserDB, OrganizationMembershipDB]]:
        """Apply an organization-user sort or the deterministic default."""
        order_by = parse_sort(
            sort=sort,
            allowed={
                "email": (func.lower(CurrentEmail.email), UserDB.id),
                "first_name": (func.lower(UserDB.first_name), UserDB.id),
                "last_name": (func.lower(UserDB.last_name), UserDB.id),
                "active": (UserDB.is_active, UserDB.id),
                "email_verified": (CurrentEmail.verified_at.is_not(None), UserDB.id),
                "created_at": (UserDB.created_at, UserDB.id),
            },
            default=(UserDB.created_at.desc(), UserDB.id.desc()),
        )
        return statement.order_by(*order_by)

    async def search(
        self, *, criteria: OrganizationUserSearchCriteriaDTO
    ) -> UserPageDTO[OrganizationUserReadDTO]:
        """Search users in the actor's organization."""
        self._require_actor()
        statement = self._search_statement(criteria=criteria)
        rows = (
            await self.db_session.execute(
                self._apply_sort(statement, sort=criteria.sort)
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

    async def get(self, *, user_id: PublicId) -> OrganizationUserReadDTO:
        """Read one user in the actor's organization."""
        user, membership = await self._target(user_id=user_id)
        return to_organization_user_read_dto(user, membership.role)

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

    async def resend_invitation(self, *, user_id: PublicId) -> None:
        """Resend an invitation to an organization user."""
        target, _membership = await self._target(user_id=user_id)
        require_organization_managed_target(target_is_operator=target.is_operator)
        await self.lifecycle.resend_invitation(target=target)

    async def patch(
        self, *, user_id: PublicId, dto: OrganizationUserPatchDTO
    ) -> OrganizationUserReadDTO:
        """Patch an organization-managed user representation."""
        command = UserUpdateCommand.model_validate(dto.model_dump(exclude_unset=True))
        if not command.changes():
            return await self.get(user_id=user_id)
        target, membership = await self._target(user_id=user_id)
        require_organization_managed_target(target_is_operator=target.is_operator)
        row, membership = await self.lifecycle.update(
            target=target,
            membership=membership,
            command=command,
            email_policy=EmailUpdatePolicy.DIRECT_IF_UNVERIFIED,
        )
        return to_organization_user_read_dto(row, membership.role)

    async def replace(
        self, *, user_id: PublicId, dto: OrganizationUserReplaceDTO
    ) -> OrganizationUserReadDTO:
        """Replace an organization-managed user representation."""
        target, membership = await self._target(user_id=user_id)
        require_organization_managed_target(target_is_operator=target.is_operator)
        row, membership = await self.lifecycle.update(
            target=target,
            membership=membership,
            command=UserUpdateCommand.model_validate(dto.model_dump()),
            email_policy=EmailUpdatePolicy.DIRECT_IF_UNVERIFIED,
        )
        return to_organization_user_read_dto(row, membership.role)

    async def delete(self, *, user_id: PublicId) -> None:
        """Delete a user from the actor's organization."""
        target, membership = await self._target(user_id=user_id)
        require_organization_managed_target(target_is_operator=target.is_operator)
        await self.lifecycle.delete(targets=((target, membership),))
