"""Actor-neutral lifecycle operations and invariants for users."""

import secrets
from collections.abc import Sequence
from datetime import datetime, UTC
from logging import getLogger
from typing import cast, TYPE_CHECKING

from sqlalchemy import delete, insert, select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm.attributes import set_committed_value

from app.auth_tokens.enums import AuthTokenPurpose
from app.db.helpers import map_integrity_error
from app.db.models.auth_token import UserAuthTokenDB
from app.db.models.organization_membership import OrganizationMembershipDB
from app.db.models.user import UserDB, UserEmailDB
from app.errors import ObjectNotFoundError
from app.events.protocols import EventPublisher
from app.events.types import (
    AccountVerificationRequested,
    EmailChangeRequested,
    InviteCreated,
)
from app.identity.errors import CurrentPasswordMismatchError
from app.identity.services.access_invariants import UserAccessInvariantService
from app.identity.services.email_lifecycle import (
    PreparedUserUpdate,
    UserEmailLifecycleService,
)
from app.identity.services.lifecycle_policy import EmailUpdatePolicy
from app.identity.users.commands import (
    UserCreateCommand,
    UserOnboardingMode,
    UserUpdateCommand,
)
from app.identity.users.dtos import UserPasswordChangeDTO
from app.identity.users.emails import create_user_email
from app.identity.users.enums import UserEmailStatus
from app.identity.users.errors import InactiveUserInvitationError
from app.identity.users.specs import UserSpecs
from app.password.async_hashing import hash_password, verify_password
from app.password.protocols import PasswordHasherProtocol
from app.public_ids import PublicId
from app.security.session_revocation import SecuritySessionRevocationService


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
        event_publisher: EventPublisher,
        security_revocation: SecuritySessionRevocationService,
        session_factory: "async_sessionmaker[AsyncSession]",
    ) -> None:
        """Initialize lifecycle collaborators bound to one transaction."""
        self.db_session = db_session
        self.password_hasher = password_hasher
        self.event_publisher = event_publisher
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
        values = command.model_dump(
            exclude={
                "email",
                "email_verified",
                "onboarding",
                "password",
                "organization_id",
                "role",
            }
        )
        password = command.password
        if password is None:
            password = secrets.token_urlsafe(UserSpecs.GENERATED_PASSWORD_BYTES)
        values["hashed_password"] = await hash_password(self.password_hasher, password)
        await self.email_lifecycle.require_available(
            email=str(command.email),
            current_user_id=None,
        )
        try:
            async with self.db_session.begin_nested():
                row = (
                    await self.db_session.execute(
                        insert(UserDB).values(**values).returning(UserDB)
                    )
                ).scalar_one()
                membership = (
                    await self.db_session.execute(
                        insert(OrganizationMembershipDB)
                        .values(
                            user_id=row.id,
                            organization_id=command.organization_id,
                            role=command.role,
                        )
                        .returning(OrganizationMembershipDB)
                    )
                ).scalar_one()
                user_email = await create_user_email(
                    self.db_session,
                    user_id=row.id,
                    email=str(command.email),
                    status=UserEmailStatus.CURRENT,
                    verified_at=datetime.now(UTC) if command.email_verified else None,
                )
                set_committed_value(row, "emails", [user_email])
                await self.db_session.flush()
        except IntegrityError as exc:
            raise map_integrity_error(exc) from exc
        if command.onboarding is UserOnboardingMode.INVITATION:
            await self.event_publisher.publish(
                InviteCreated(
                    user_public_id=PublicId(row.public_id),
                    user_email_id=user_email.id,
                )
            )
        else:
            await self.event_publisher.publish(
                AccountVerificationRequested(
                    user_public_id=PublicId(row.public_id),
                    user_email_id=user_email.id,
                )
            )
        return row, membership

    @staticmethod
    def _revokes_sessions(
        *,
        target: UserDB,
        membership: OrganizationMembershipDB,
        prepared: PreparedUserUpdate,
        role: object | None,
        organization_id: object | None,
    ) -> bool:
        """Return whether a mutation changes authentication or authorization."""
        security_fields = (
            "hashed_password",
            "is_active",
            "is_operator",
        )
        user_security_changed = any(
            field in prepared.changes
            and prepared.changes[field] != getattr(target, field, None)
            for field in security_fields
        )
        role_changed = role is not None and role != membership.role
        organization_changed = (
            organization_id is not None
            and organization_id != membership.organization_id
        )
        return (
            user_security_changed
            or prepared.email_security_changed
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
        prepared = await self.email_lifecycle.prepare_update(
            target=target,
            command=command,
            policy=email_policy,
        )
        role = prepared.changes.pop("role", None)
        organization_id = prepared.changes.pop("organization_id", None)
        if (
            not prepared.changes
            and role is None
            and organization_id is None
            and not prepared.resend_invite
            and not prepared.send_email_change
            and not prepared.email_security_changed
        ):
            return target, membership
        revoke_sessions = self._revokes_sessions(
            target=target,
            membership=membership,
            prepared=prepared,
            role=role,
            organization_id=organization_id,
        )
        deactivates_user = (
            target.is_active and prepared.changes.get("is_active") is False
        )
        row = target
        if prepared.changes:
            row = (
                await self.db_session.execute(
                    update(UserDB)
                    .where(UserDB.id == target.id)
                    .values(**prepared.changes)
                    .returning(UserDB)
                )
            ).scalar_one()
        membership_changes: dict[str, object] = {}
        if role is not None:
            membership_changes["role"] = role
        if organization_id is not None:
            membership_changes["organization_id"] = organization_id
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
                reason="user_auth_changed",
            )
        if deactivates_user:
            await self.db_session.execute(
                update(UserAuthTokenDB)
                .where(
                    UserAuthTokenDB.user_email_id.in_(
                        select(UserEmailDB.id).where(UserEmailDB.user_id == row.id)
                    )
                )
                .where(UserAuthTokenDB.purpose == AuthTokenPurpose.reset_password)
                .where(UserAuthTokenDB.used_at.is_(None))
                .values(used_at=datetime.now(UTC))
            )
        await self.db_session.flush()
        await self.db_session.refresh(row)
        if prepared.send_email_change:
            pending = row.pending_email_record
            if pending is None:
                msg = f"User {row.id} has no pending email to confirm."
                raise RuntimeError(msg)
            await self.event_publisher.publish(
                EmailChangeRequested(
                    user_public_id=PublicId(row.public_id),
                    user_email_id=pending.id,
                )
            )
        if prepared.resend_invite:
            current = row.current_email
            await self.event_publisher.publish(
                InviteCreated(
                    user_public_id=PublicId(row.public_id),
                    user_email_id=current.id,
                )
            )
        return row, membership

    async def resend_invitation(self, *, target: UserDB) -> None:
        """Publish a new invitation for an active, unverified user."""
        if not target.is_active:
            raise InactiveUserInvitationError
        if not target.email_verified:
            current = target.current_email
            await self.event_publisher.publish(
                InviteCreated(
                    user_public_id=PublicId(target.public_id),
                    user_email_id=current.id,
                )
            )

    async def change_password_autonomously(
        self, *, target: UserDB, data: UserPasswordChangeDTO
    ) -> None:
        """Verify and replace a password using a dedicated short write."""
        previous_hash = target.hashed_password
        # The target is fully materialized; release its read transaction before
        # running the expensive password verification and replacement hash.
        await self.db_session.commit()
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
                .where(UserDB.id == target.id)
                .where(UserDB.hashed_password == previous_hash)
                .where(UserDB.is_active.is_(True))
                .values(hashed_password=new_hash)
                .returning(UserDB.id)
            )
            if changed_user_id is None:
                raise CurrentPasswordMismatchError
            await write_session.execute(
                update(UserAuthTokenDB)
                .where(
                    UserAuthTokenDB.user_email_id.in_(
                        select(UserEmailDB.id).where(UserEmailDB.user_id == target.id)
                    )
                )
                .where(UserAuthTokenDB.purpose == AuthTokenPurpose.reset_password)
                .where(UserAuthTokenDB.used_at.is_(None))
                .values(used_at=datetime.now(UTC))
            )
            await SecuritySessionRevocationService(
                db_session=write_session
            ).revoke_user_security_sessions(
                user_id=target.id,
                reason="password_changed",
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
