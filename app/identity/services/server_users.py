"""Server-wide user service."""

from uuid import UUID

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.sql import Select

from app.core.errors.common import ForbiddenOperationError, ObjectNotFoundError
from app.db.models.organization import OrganizationDB
from app.db.models.organization_membership import OrganizationMembershipDB
from app.db.models.user import UserDB, UserEmailDB
from app.identity.services.lifecycle import UserLifecycleService
from app.identity.users.commands import (
    UserCreateCommand,
    UserOnboardingMode,
    UserUpdateCommand,
)
from app.identity.users.criteria import ServerUserSearchCriteriaDTO, UserPageDTO
from app.identity.users.dtos import (
    ServerUserCreateDTO,
    ServerUserPatchDTO,
    ServerUserReplaceDTO,
    to_user_read_dto,
    UserReadDTO,
    UserSessionTargetDTO,
)
from app.identity.users.emails import active_email_loader
from app.identity.users.enums import EmailUpdatePolicy, UserEmailStatus
from app.identity.users.query import boolean_state_filter, compact_filters
from app.identity.users.search import (
    apply_user_search_sort,
    join_user_search_emails,
    user_search_filters,
)
from app.security.principals import UserPrincipalContext


class ServerUsersService:
    """Manage users through the server control-plane boundary."""

    def __init__(
        self,
        *,
        db_session: AsyncSession,
        actor_ctx: UserPrincipalContext,
        lifecycle: UserLifecycleService,
    ) -> None:
        """Initialize global user administration."""
        self.db_session = db_session
        self.actor_ctx = actor_ctx
        self.lifecycle = lifecycle

    def _require_actor(self) -> None:
        """Require server-operator authority."""
        if not self.actor_ctx.is_operator:
            raise ForbiddenOperationError

    async def _target(
        self, *, user_id: UUID
    ) -> tuple[UserDB, OrganizationMembershipDB, UUID]:
        """Resolve a global target and its public organization identifier."""
        self._require_actor()
        row = (
            await self.db_session.execute(
                select(UserDB, OrganizationMembershipDB, OrganizationDB.public_id)
                .options(active_email_loader())
                .join(
                    OrganizationMembershipDB,
                    OrganizationMembershipDB.user_id == UserDB.id,
                )
                .join(
                    OrganizationDB,
                    OrganizationDB.id == OrganizationMembershipDB.organization_id,
                )
                .where(UserDB.public_id == user_id)
            )
        ).one_or_none()
        if row is None:
            raise ObjectNotFoundError
        target, membership, organization_public_id = row
        return target, membership, organization_public_id

    async def _resolve_organization_id(self, *, public_id: UUID) -> int:
        """Resolve a public organization identifier for an operator mutation."""
        organization_id = await self.db_session.scalar(
            select(OrganizationDB.id).where(OrganizationDB.public_id == public_id)
        )
        if organization_id is None:
            raise ObjectNotFoundError
        return int(organization_id)

    @staticmethod
    def _search_statement(
        *, criteria: ServerUserSearchCriteriaDTO
    ) -> Select[tuple[UserDB, OrganizationMembershipDB, UUID]]:
        """Build a global user search statement."""
        statement = join_user_search_emails(
            select(UserDB, OrganizationMembershipDB, OrganizationDB.public_id)
            .options(active_email_loader())
            .join(
                OrganizationMembershipDB,
                OrganizationMembershipDB.user_id == UserDB.id,
            )
            .join(
                OrganizationDB,
                OrganizationDB.id == OrganizationMembershipDB.organization_id,
            )
        )
        statement = statement.where(
            *user_search_filters(criteria=criteria),
            *compact_filters(
                boolean_state_filter(UserDB.is_operator, value=criteria.operator)
            ),
        )
        if criteria.organization_id is not None:
            statement = statement.where(
                OrganizationDB.public_id == criteria.organization_id
            )
        return statement

    async def search(
        self, *, criteria: ServerUserSearchCriteriaDTO
    ) -> UserPageDTO[UserReadDTO]:
        """Search users across all organizations."""
        self._require_actor()
        statement = self._search_statement(criteria=criteria)
        result = (
            await self.db_session.execute(
                apply_user_search_sort(
                    statement,
                    sort=criteria.sort,
                    additional_sorts={
                        "operator": (UserDB.is_operator, UserDB.id),
                    },
                )
                .offset(criteria.offset)
                .limit(criteria.limit)
            )
        ).all()
        rows = [
            (user, membership, organization_public_id)
            for user, membership, organization_public_id in result
        ]
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
                to_user_read_dto(user, organization_public_id, membership.role)
                for user, membership, organization_public_id in rows
            ],
            total=total,
        )

    async def get(self, *, user_id: UUID) -> UserReadDTO:
        """Read one user across organizations."""
        user, membership, organization_public_id = await self._target(user_id=user_id)
        return to_user_read_dto(user, organization_public_id, membership.role)

    async def get_session_target(self, *, user_id: UUID) -> UserSessionTargetDTO:
        """Return a minimal operator-authorized session target in one query."""
        self._require_actor()
        target = (
            await self.db_session.execute(
                select(UserDB.id, UserEmailDB.email)
                .join(
                    OrganizationMembershipDB,
                    OrganizationMembershipDB.user_id == UserDB.id,
                )
                .join(UserEmailDB, UserEmailDB.user_id == UserDB.id)
                .where(UserDB.public_id == user_id)
                .where(UserEmailDB.status == UserEmailStatus.CURRENT)
            )
        ).one_or_none()
        if target is None:
            raise ObjectNotFoundError
        internal_user_id, email = target
        return UserSessionTargetDTO(
            internal_user_id=internal_user_id,
            email=email,
        )

    async def create(self, *, dto: ServerUserCreateDTO) -> UserReadDTO:
        """Invite a user into an operator-selected organization."""
        self._require_actor()
        internal_organization_id = await self._resolve_organization_id(
            public_id=dto.organization_id
        )
        row, membership = await self.lifecycle.create(
            command=UserCreateCommand(
                organization_id=internal_organization_id,
                onboarding=UserOnboardingMode.INVITATION,
                **dto.model_dump(exclude={"organization_id"}),
            ),
        )
        return to_user_read_dto(row, dto.organization_id, membership.role)

    async def resend_invitation(self, *, user_id: UUID) -> None:
        """Resend an invitation to any user."""
        target, _membership, _organization_public_id = await self._target(
            user_id=user_id
        )
        await self.lifecycle.resend_invitation(target=target)

    async def patch(
        self,
        *,
        user_id: UUID,
        dto: ServerUserPatchDTO,
    ) -> UserReadDTO:
        """Patch a user across organizations."""
        target, membership, current_organization_public_id = await self._target(
            user_id=user_id
        )
        values = dto.model_dump(exclude={"organization_id"}, exclude_unset=True)
        output_organization_public_id = current_organization_public_id
        if dto.organization_id is not None:
            values["organization_id"] = await self._resolve_organization_id(
                public_id=dto.organization_id
            )
            output_organization_public_id = dto.organization_id
        if not values:
            return to_user_read_dto(
                target, current_organization_public_id, membership.role
            )
        command = UserUpdateCommand.model_validate(values)
        row, membership = await self.lifecycle.update(
            target=target,
            membership=membership,
            command=command,
            email_policy=EmailUpdatePolicy.DIRECT_IF_UNVERIFIED,
        )
        return to_user_read_dto(row, output_organization_public_id, membership.role)

    async def replace(
        self,
        *,
        user_id: UUID,
        dto: ServerUserReplaceDTO,
    ) -> UserReadDTO:
        """Replace a user across organizations."""
        target, membership, _organization_public_id = await self._target(
            user_id=user_id
        )
        values = dto.model_dump(exclude={"organization_id"})
        values["organization_id"] = await self._resolve_organization_id(
            public_id=dto.organization_id
        )
        row, membership = await self.lifecycle.update(
            target=target,
            membership=membership,
            command=UserUpdateCommand.model_validate(values),
            email_policy=EmailUpdatePolicy.DIRECT_IF_UNVERIFIED,
        )
        return to_user_read_dto(row, dto.organization_id, membership.role)

    async def delete(self, *, user_id: UUID) -> None:
        """Delete a user across organizations."""
        target, membership, _organization_public_id = await self._target(
            user_id=user_id
        )
        await self.lifecycle.delete(targets=((target, membership),))
