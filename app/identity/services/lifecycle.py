"""Actor-neutral lifecycle operations and invariants for users."""

import secrets
from collections.abc import Sequence
from logging import getLogger
from typing import cast, TYPE_CHECKING

from sqlalchemy import delete, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.browser_sessions.enums import BrowserSessionRevocationReason
from app.core.errors.common import ObjectNotFoundError
from app.db.helpers import map_integrity_error
from app.db.models.organization_membership import OrganizationMembershipDB
from app.db.models.user import UserDB
from app.identity.errors import CurrentPasswordMismatchError
from app.identity.services.access_invariants import UserAccessInvariantService
from app.identity.services.email_lifecycle import (
    EmailUpdateEffects,
    UserEmailLifecycleService,
)
from app.identity.users.commands import (
    UserCreateCommand,
    UserOnboardingMode,
    UserUpdateCommand,
)
from app.identity.users.creation import create_user_identity
from app.identity.users.dtos import UserPasswordChangeDTO
from app.identity.users.enums import (
    EmailUpdatePolicy,
    OrganizationMembershipRole,
)
from app.identity.users.errors import InactiveUserInvitationError
from app.identity.users.specs import UserSpecs
from app.notifications.events import (
    AccountVerificationRequested,
    EmailChangeRequested,
    InviteCreated,
)
from app.notifications.protocols import NotificationPublisher
from app.password.async_hashing import hash_password, verify_password
from app.password.protocols import PasswordHasherProtocol
from app.security.session_revocation import SecuritySessionRevocationService
from app.workflow_tokens.service import (
    invalidate_active_credential_tokens,
    invalidate_all_active_workflow_tokens,
)


if TYPE_CHECKING:
    from sqlalchemy.engine import CursorResult
    from sqlalchemy.ext.asyncio import async_sessionmaker


logger = getLogger(__name__)


class UserLifecycleService:
    """Apply user mutations without deciding who may target the user."""

    def __init__(
        self,
        *,
        db_session: AsyncSession,
        password_hasher: PasswordHasherProtocol,
        notification_publisher: NotificationPublisher,
        security_revocation: SecuritySessionRevocationService,
        session_factory: "async_sessionmaker[AsyncSession]",
    ) -> None:
        """Initialize lifecycle collaborators bound to one transaction."""
        self.db_session = db_session
        self.password_hasher = password_hasher
        self.notification_publisher = notification_publisher
        self.security_revocation = security_revocation
        self.session_factory = session_factory
        self.email_lifecycle = UserEmailLifecycleService(db_session)
        self.access_invariants = UserAccessInvariantService(db_session)

    async def create(
        self,
        *,
        command: UserCreateCommand,
    ) -> tuple[UserDB, OrganizationMembershipDB]:
        """Create a user and atomically reserve its normalized email."""
        password = command.password
        if password is None:
            password = secrets.token_urlsafe(UserSpecs.GENERATED_PASSWORD_BYTES)
        hashed_password = await hash_password(self.password_hasher, password)
        await self.email_lifecycle.require_available(
            email=str(command.email),
            current_user_id=None,
        )
        try:
            async with self.db_session.begin_nested():
                row, membership, user_email = await create_user_identity(
                    self.db_session,
                    command=command,
                    hashed_password=hashed_password,
                )
        except IntegrityError as exc:
            raise map_integrity_error(exc) from exc
        if command.onboarding is UserOnboardingMode.INVITATION:
            await self.notification_publisher.publish(
                InviteCreated(
                    user_public_id=row.public_id,
                    user_email_id=user_email.id,
                )
            )
        else:
            await self.notification_publisher.publish(
                AccountVerificationRequested(
                    user_public_id=row.public_id,
                    user_email_id=user_email.id,
                )
            )
        return row, membership

    @staticmethod
    def _revokes_sessions(
        *,
        target: UserDB,
        membership: OrganizationMembershipDB,
        effects: EmailUpdateEffects,
    ) -> bool:
        """Return whether a mutation changes authentication or authorization."""
        user_security_changed = (
            effects.user_changes.is_active is not None
            and effects.user_changes.is_active != target.is_active
        ) or (
            effects.user_changes.is_operator is not None
            and effects.user_changes.is_operator != target.is_operator
        )
        role_changed = effects.role is not None and effects.role != membership.role
        organization_changed = (
            effects.organization_id is not None
            and effects.organization_id != membership.organization_id
        )
        return (
            user_security_changed
            or effects.email_security_changed
            or role_changed
            or organization_changed
        )

    async def update(
        self,
        *,
        target: UserDB,
        membership: OrganizationMembershipDB,
        command: UserUpdateCommand,
        email_policy: EmailUpdatePolicy,
    ) -> tuple[UserDB, OrganizationMembershipDB]:
        """Update one resolved user while preserving lifecycle invariants."""
        await self.access_invariants.protect_update(
            target=target,
            membership=membership,
            command=command,
        )
        effects = await self.email_lifecycle.apply_update(
            target=target,
            command=command,
            policy=email_policy,
        )
        user_changes = effects.user_changes.values()
        if (
            not user_changes
            and effects.role is None
            and effects.organization_id is None
            and not effects.resend_invite
            and not effects.send_email_change
            and not effects.email_security_changed
        ):
            return target, membership
        revoke_sessions = self._revokes_sessions(
            target=target,
            membership=membership,
            effects=effects,
        )
        deactivates_user = target.is_active and effects.user_changes.is_active is False
        row = target
        if user_changes:
            row = (
                await self.db_session.execute(
                    update(UserDB)
                    .where(UserDB.id == target.id)
                    .values(**user_changes)
                    .returning(UserDB)
                )
            ).scalar_one()
        membership_changes: dict[str, int | OrganizationMembershipRole] = {}
        if effects.role is not None:
            membership_changes["role"] = effects.role
        if effects.organization_id is not None:
            membership_changes["organization_id"] = effects.organization_id
        if membership_changes:
            membership = (
                await self.db_session.execute(
                    update(OrganizationMembershipDB)
                    .where(OrganizationMembershipDB.user_id == target.id)
                    .values(**membership_changes)
                    .returning(OrganizationMembershipDB)
                )
            ).scalar_one()
        if revoke_sessions:
            await self.security_revocation.revoke_user_security_sessions(
                user_id=row.id,
                browser_reason=BrowserSessionRevocationReason.USER_AUTH_CHANGED,
            )
        if deactivates_user:
            await invalidate_all_active_workflow_tokens(
                self.db_session,
                user_id=row.id,
            )
        await self.db_session.flush()
        await self.db_session.refresh(row)
        if effects.send_email_change:
            pending = row.pending_email_record
            if pending is None:
                msg = f"User {row.id} has no pending email to confirm."
                raise RuntimeError(msg)
            await self.notification_publisher.publish(
                EmailChangeRequested(
                    user_public_id=row.public_id,
                    user_email_id=pending.id,
                )
            )
        if effects.resend_invite and row.invitation_pending:
            current = row.current_email
            await self.notification_publisher.publish(
                InviteCreated(
                    user_public_id=row.public_id,
                    user_email_id=current.id,
                )
            )
        return row, membership

    async def resend_invitation(self, *, target: UserDB) -> None:
        """Publish a new invitation for an active, unverified user."""
        if not target.is_active:
            raise InactiveUserInvitationError
        if target.invitation_pending and not target.email_verified:
            current = target.current_email
            await self.notification_publisher.publish(
                InviteCreated(
                    user_public_id=target.public_id,
                    user_email_id=current.id,
                )
            )

    async def change_password_autonomously(
        self, *, target: UserDB, data: UserPasswordChangeDTO
    ) -> None:
        """Verify and replace a password using a dedicated short write."""
        target_id = target.id
        previous_hash = target.hashed_password
        # This autonomous operation cannot compose with request-scoped writes.
        # Discard session sliding before running expensive password hashing.
        await self.db_session.rollback()
        if not await verify_password(
            self.password_hasher,
            password=data.current_password,
            password_hash=previous_hash,
        ):
            raise CurrentPasswordMismatchError
        new_hash = await hash_password(self.password_hasher, data.new_password)
        async with self.session_factory.begin() as write_session:
            changed_user_id = await write_session.scalar(
                update(UserDB)
                .where(UserDB.id == target_id)
                .where(UserDB.hashed_password == previous_hash)
                .where(UserDB.is_active.is_(True))
                .values(hashed_password=new_hash, invitation_pending=False)
                .returning(UserDB.id)
            )
            if changed_user_id is None:
                raise CurrentPasswordMismatchError
            await invalidate_active_credential_tokens(
                write_session,
                user_id=target_id,
            )
            await SecuritySessionRevocationService(
                db_session=write_session
            ).revoke_user_security_sessions(
                user_id=target_id,
                browser_reason=BrowserSessionRevocationReason.PASSWORD_CHANGED,
            )

    async def delete(
        self, *, targets: Sequence[tuple[UserDB, OrganizationMembershipDB]]
    ) -> int:
        """Delete resolved users after preserving access invariants."""
        if not targets:
            return 0
        target_ids = {target.id for target, _role in targets}
        await self.access_invariants.protect_delete(targets=targets)

        result = cast(
            "CursorResult[object]",
            await self.db_session.execute(
                delete(UserDB).where(UserDB.id.in_(target_ids))
            ),
        )
        await self.db_session.flush()
        deleted_count = int(result.rowcount or 0)
        if deleted_count != len(target_ids):
            logger.error(
                "Expected to delete %s users but deleted %s.",
                len(target_ids),
                deleted_count,
            )
            raise ObjectNotFoundError
        return deleted_count
