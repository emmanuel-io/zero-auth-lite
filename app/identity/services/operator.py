"""Server-operator user service."""

from sqlalchemy import and_, func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import aliased
from sqlalchemy.sql import Select

from app.db.models.organization import OrganizationDB
from app.db.models.organization_membership import OrganizationMembershipDB
from app.db.models.user import UserDB, UserEmailDB
from app.errors import ForbiddenOperationError, ObjectNotFoundError
from app.identity.services.lifecycle import UserLifecycleService
from app.identity.services.lifecycle_policy import EmailUpdatePolicy
from app.identity.users.commands import (
    UserCreateCommand,
    UserOnboardingMode,
    UserUpdateCommand,
)
from app.identity.users.criteria import OperatorUserSearchCriteriaDTO, UserPageDTO
from app.identity.users.dtos import (
    OperatorUserCreateDTO,
    OperatorUserPatchDTO,
    OperatorUserReplaceDTO,
    to_user_read_dto,
    UserReadDTO,
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


class OperatorUsersService:
    """Manage users through the server-operator boundary."""

    def __init__(
        self,
        *,
        db_session: AsyncSession,
        user_ctx: UserPrincipalContext,
        lifecycle: UserLifecycleService,
    ) -> None:
        """Initialize global user administration."""
        self.db_session = db_session
        self.actor_ctx = user_ctx
        self.lifecycle = lifecycle

    def _require_actor(self) -> None:
        """Require server-operator authority."""
        if not self.actor_ctx.is_operator:
            raise ForbiddenOperationError

    async def _target(
        self, *, user_id: PublicId
    ) -> tuple[UserDB, OrganizationMembershipDB, int]:
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
        return target, membership, int(organization_public_id)

    async def _resolve_organization_id(self, *, public_id: PublicId) -> int:
        """Resolve a public organization identifier for an operator mutation."""
        organization_id = await self.db_session.scalar(
            select(OrganizationDB.id).where(OrganizationDB.public_id == public_id)
        )
        if organization_id is None:
            raise ObjectNotFoundError
        return int(organization_id)

    @staticmethod
    def _search_statement(
        *, criteria: OperatorUserSearchCriteriaDTO
    ) -> Select[tuple[UserDB, OrganizationMembershipDB, PublicId]]:
        """Build a global user search statement."""
        statement = (
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
        )
        statement = statement.where(
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
                boolean_state_filter(UserDB.is_operator, value=criteria.operator),
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
        if criteria.organization_id is not None:
            statement = statement.where(
                OrganizationDB.public_id == criteria.organization_id
            )
        return statement

    @staticmethod
    def _apply_sort(
        statement: Select[tuple[UserDB, OrganizationMembershipDB, PublicId]],
        *,
        sort: str | None,
    ) -> Select[tuple[UserDB, OrganizationMembershipDB, PublicId]]:
        """Apply an operator-user sort or the deterministic default."""
        order_by = parse_sort(
            sort=sort,
            allowed={
                "email": (func.lower(CurrentEmail.email), UserDB.id),
                "first_name": (func.lower(UserDB.first_name), UserDB.id),
                "last_name": (func.lower(UserDB.last_name), UserDB.id),
                "active": (UserDB.is_active, UserDB.id),
                "email_verified": (CurrentEmail.verified_at.is_not(None), UserDB.id),
                "operator": (UserDB.is_operator, UserDB.id),
                "created_at": (UserDB.created_at, UserDB.id),
            },
            default=(UserDB.created_at.desc(), UserDB.id.desc()),
        )
        return statement.order_by(*order_by)

    async def search(
        self, *, criteria: OperatorUserSearchCriteriaDTO
    ) -> UserPageDTO[UserReadDTO]:
        """Search users across all organizations."""
        self._require_actor()
        statement = self._search_statement(criteria=criteria)
        result = (
            await self.db_session.execute(
                self._apply_sort(statement, sort=criteria.sort)
                .offset(criteria.offset)
                .limit(criteria.limit)
            )
        ).all()
        rows = [
            (user, membership, int(organization_public_id))
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

    async def get(self, *, user_id: PublicId) -> UserReadDTO:
        """Read one user across organizations."""
        user, membership, organization_public_id = await self._target(user_id=user_id)
        return to_user_read_dto(user, organization_public_id, membership.role)

    async def create(self, *, dto: OperatorUserCreateDTO) -> UserReadDTO:
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
        return to_user_read_dto(row, int(dto.organization_id), membership.role)

    async def resend_invitation(self, *, user_id: PublicId) -> None:
        """Resend an invitation to any user."""
        target, _membership, _organization_public_id = await self._target(
            user_id=user_id
        )
        await self.lifecycle.resend_invitation(target=target)

    async def patch(
        self,
        *,
        user_id: PublicId,
        dto: OperatorUserPatchDTO,
    ) -> UserReadDTO:
        """Patch a user across organizations."""
        target, membership, current_organization_public_id = await self._target(
            user_id=user_id
        )
        values = dto.model_dump(exclude={"organization_id"}, exclude_unset=True)
        output_organization_id = current_organization_public_id
        if dto.organization_id is not None:
            values["organization_id"] = await self._resolve_organization_id(
                public_id=dto.organization_id
            )
            output_organization_id = int(dto.organization_id)
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
        return to_user_read_dto(row, output_organization_id, membership.role)

    async def replace(
        self,
        *,
        user_id: PublicId,
        dto: OperatorUserReplaceDTO,
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
        return to_user_read_dto(row, int(dto.organization_id), membership.role)

    async def delete(self, *, user_id: PublicId) -> None:
        """Delete a user across organizations."""
        target, membership, _organization_public_id = await self._target(
            user_id=user_id
        )
        await self.lifecycle.delete(targets=((target, membership),))
