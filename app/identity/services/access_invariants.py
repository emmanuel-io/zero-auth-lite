"""Concurrency-safe administrator invariants for user mutations."""

from collections.abc import Sequence

from sqlalchemy import func, select, text
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models.organization_membership import OrganizationMembershipDB
from app.db.models.user import UserDB, UserEmailDB
from app.identity.users.commands import UserUpdateCommand
from app.identity.users.enums import OrganizationUserRole, UserEmailStatus
from app.identity.users.errors import (
    LastActiveOperatorError,
    LastActiveOrganizationAdminError,
)


class UserAccessInvariantService:
    """Protect the final accessible organization admin and server operator."""

    def __init__(self, db_session: AsyncSession) -> None:
        """Bind invariant checks to the lifecycle transaction."""
        self.db_session = db_session

    async def _acquire_write_lock(self, *, user_id: int) -> None:
        """Serialize checks through SQLite's single-writer lock."""
        await self.db_session.execute(
            text('UPDATE "user" SET id = id WHERE id = :user_id'),
            {"user_id": user_id},
        )

    async def _require_other_organization_admin(
        self, membership: OrganizationMembershipDB
    ) -> None:
        """Require another active verified administrator in the organization."""
        count = await self.db_session.scalar(
            select(func.count())
            .select_from(UserDB)
            .join(
                OrganizationMembershipDB,
                OrganizationMembershipDB.user_id == UserDB.id,
            )
            .join(UserEmailDB, UserEmailDB.user_id == UserDB.id)
            .where(
                OrganizationMembershipDB.organization_id == membership.organization_id
            )
            .where(OrganizationMembershipDB.role == OrganizationUserRole.ADMIN)
            .where(UserDB.is_active.is_(True))
            .where(
                UserEmailDB.status == UserEmailStatus.CURRENT,
                UserEmailDB.verified_at.is_not(None),
            )
        )
        if int(count or 0) <= 1:
            raise LastActiveOrganizationAdminError

    async def _require_other_operator(self) -> None:
        """Require another active verified server operator."""
        count = await self.db_session.scalar(
            select(func.count())
            .select_from(UserDB)
            .join(UserEmailDB, UserEmailDB.user_id == UserDB.id)
            .where(UserDB.is_operator.is_(True))
            .where(UserDB.is_active.is_(True))
            .where(
                UserEmailDB.status == UserEmailStatus.CURRENT,
                UserEmailDB.verified_at.is_not(None),
            )
        )
        if int(count or 0) <= 1:
            raise LastActiveOperatorError

    async def protect_update(
        self,
        *,
        target: UserDB,
        membership: OrganizationMembershipDB,
        command: UserUpdateCommand,
    ) -> None:
        """Reject an update that removes the final accessible admin role."""
        changes = command.changes()
        accessible = target.is_active and target.email_verified
        removes_organization_admin = (
            membership.role is OrganizationUserRole.ADMIN
            and accessible
            and (
                changes.get("role") is OrganizationUserRole.MEMBER
                or changes.get("is_active") is False
                or changes.get("email_verified") is False
                or changes.get("organization_id")
                not in {None, membership.organization_id}
            )
        )
        removes_operator = (
            target.is_operator
            and accessible
            and (
                changes.get("is_operator") is False
                or changes.get("is_active") is False
                or changes.get("email_verified") is False
            )
        )
        if removes_operator or removes_organization_admin:
            await self._acquire_write_lock(user_id=target.id)
        if removes_operator:
            await self._require_other_operator()
        if removes_organization_admin:
            await self._require_other_organization_admin(membership)

    async def protect_delete(
        self, *, targets: Sequence[tuple[UserDB, OrganizationMembershipDB]]
    ) -> None:
        """Reject deletion of the final accessible admin in either scope."""
        if not targets:
            return
        target_ids = {target.id for target, _role in targets}
        protects_operator = any(
            target.is_operator and target.is_active and target.email_verified
            for target, _role in targets
        )
        organization_ids = {
            membership.organization_id
            for target, membership in targets
            if membership.role is OrganizationUserRole.ADMIN
            and target.is_active
            and target.email_verified
        }
        if protects_operator or organization_ids:
            await self._acquire_write_lock(user_id=min(target_ids))
        if protects_operator:
            remaining = await self.db_session.scalar(
                select(func.count())
                .select_from(UserDB)
                .join(UserEmailDB, UserEmailDB.user_id == UserDB.id)
                .where(UserDB.is_operator.is_(True))
                .where(UserDB.is_active.is_(True))
                .where(
                    UserEmailDB.status == UserEmailStatus.CURRENT,
                    UserEmailDB.verified_at.is_not(None),
                )
                .where(UserDB.id.not_in(target_ids))
            )
            if int(remaining or 0) == 0:
                raise LastActiveOperatorError

        for organization_id in sorted(organization_ids):
            remaining = await self.db_session.scalar(
                select(func.count())
                .select_from(UserDB)
                .join(
                    OrganizationMembershipDB,
                    OrganizationMembershipDB.user_id == UserDB.id,
                )
                .join(UserEmailDB, UserEmailDB.user_id == UserDB.id)
                .where(OrganizationMembershipDB.organization_id == organization_id)
                .where(OrganizationMembershipDB.role == OrganizationUserRole.ADMIN)
                .where(UserDB.is_active.is_(True))
                .where(
                    UserEmailDB.status == UserEmailStatus.CURRENT,
                    UserEmailDB.verified_at.is_not(None),
                )
                .where(UserDB.id.not_in(target_ids))
            )
            if int(remaining or 0) == 0:
                raise LastActiveOrganizationAdminError
