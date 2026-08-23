"""Credential authentication and browser-session creation."""

import secrets
from datetime import datetime, timedelta, UTC
from logging import getLogger
from typing import TYPE_CHECKING

from sqlalchemy import delete, select, text
from sqlalchemy.ext.asyncio import AsyncSession

from app.browser_sessions.dtos import LoginResultDTO, SessionCreateDTO
from app.browser_sessions.errors import InvalidLoginCredentialsError
from app.browser_sessions.hashing import (
    DUMMY_PASSWORD_HASH,
    hash_auth_identifier,
    hash_session_id,
    hash_session_metadata,
)
from app.browser_sessions.settings import SessionSettings
from app.browser_sessions.specs import SessionSpecs
from app.db.models.browser_session import BrowserSessionDB
from app.db.models.organization import OrganizationDB
from app.db.models.organization_membership import OrganizationMembershipDB
from app.db.models.user import UserDB, UserEmailDB
from app.identity.dtos import IdentityDTO, IdentityUserDTO
from app.identity.mapping import to_identity
from app.identity.public_ids import format_organization_id, format_user_id
from app.identity.users.emails import active_email_loader, normalize_email
from app.identity.users.enums import UserEmailStatus
from app.password.async_hashing import verify_password
from app.password.protocols import PasswordHasherProtocol


if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import async_sessionmaker


logger = getLogger(__name__)


class SessionAuthenticationService:
    """Authenticate credentials and create browser sessions."""

    def __init__(
        self,
        db_session: AsyncSession,
        settings: SessionSettings,
        password_hasher: PasswordHasherProtocol,
        session_factory: "async_sessionmaker[AsyncSession]",
    ) -> None:
        """Initialize the browser-session authentication workflow."""
        self.db_session = db_session
        self.settings = settings
        self.password_hasher = password_hasher
        self.session_factory = session_factory

    def _hash_session_id(self, *, session_id: str) -> str:
        """Return the configured database lookup digest for a raw session ID."""
        return hash_session_id(
            session_id=session_id,
            secret=self.settings.id_hash_secret.get_secret_value(),
        )

    def _hash_auth_identifier(self, *, value: str) -> str:
        """Return the configured log-safe digest for an auth identifier."""
        return hash_auth_identifier(
            value=value,
            secret=self.settings.id_hash_secret.get_secret_value(),
        )

    async def _get_identity_by_email(self, *, email: str) -> IdentityDTO | None:
        """Get an application identity by normalized email."""
        async with self.session_factory() as read_session:
            row = (
                await read_session.execute(
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
                    .join(UserEmailDB, UserEmailDB.user_id == UserDB.id)
                    .where(
                        UserEmailDB.normalized_email == normalize_email(email),
                        UserEmailDB.status == UserEmailStatus.CURRENT,
                    )
                )
            ).one_or_none()
        return to_identity(row) if row is not None else None

    async def _lock_if_login_state_unchanged(self, *, user: IdentityUserDTO) -> bool:
        """Lock the writer only if the credential and login state are unchanged.

        Password verification deliberately runs outside a SQLite transaction.
        This conditional no-op update closes the resulting race with password
        changes before the new browser session is inserted.
        """
        authenticated_user_id = await self.db_session.scalar(
            text(
                'UPDATE "user" SET id = id '
                "WHERE id = :user_id "
                "AND hashed_password = :hashed_password "
                "AND is_active = 1 "
                "AND EXISTS ("
                "SELECT 1 FROM user_email "
                "WHERE user_email.user_id = user.id "
                "AND user_email.status = 'current' "
                "AND user_email.verified_at IS NOT NULL"
                ") "
                "RETURNING id"
            ),
            {
                "user_id": user.id,
                "hashed_password": user.hashed_password,
            },
        )
        return authenticated_user_id is not None

    async def login(
        self,
        *,
        email: str,
        password: str,
        source_ip: str | None = None,
        user_agent: str | None = None,
    ) -> LoginResultDTO:
        """Authenticate the user and create a browser session."""
        email_hash = self._hash_auth_identifier(value=email)
        identity = await self._get_identity_by_email(email=email)
        if identity is None:
            logger.warning(
                "event=browser_login outcome=failure reason=unknown_user email_hash=%s",
                email_hash,
            )
            await verify_password(
                self.password_hasher,
                password=password,
                password_hash=DUMMY_PASSWORD_HASH,
            )
            raise InvalidLoginCredentialsError

        user = identity.user
        password_valid = await verify_password(
            self.password_hasher,
            password=password,
            password_hash=user.hashed_password,
        )
        if not password_valid:
            logger.warning(
                (
                    "event=browser_login outcome=failure reason=invalid_password "
                    "email_hash=%s"
                ),
                email_hash,
            )
            raise InvalidLoginCredentialsError
        if not user.is_active:
            logger.warning(
                (
                    "event=browser_login outcome=failure reason=inactive_user "
                    "email_hash=%s"
                ),
                email_hash,
            )
            raise InvalidLoginCredentialsError
        if not user.email_verified:
            logger.warning(
                (
                    "event=browser_login outcome=failure reason=unverified_user "
                    "email_hash=%s"
                ),
                email_hash,
            )
            raise InvalidLoginCredentialsError

        if not await self._lock_if_login_state_unchanged(user=user):
            logger.warning(
                (
                    "event=browser_login outcome=failure reason=state_changed "
                    "email_hash=%s"
                ),
                email_hash,
            )
            raise InvalidLoginCredentialsError

        session_id = secrets.token_urlsafe(SessionSpecs.TOKEN_BYTES)
        csrf = secrets.token_urlsafe(SessionSpecs.TOKEN_BYTES)
        now = datetime.now(tz=UTC)
        absolute_expires_at = now + timedelta(
            seconds=self.settings.absolute_ttl_seconds
        )
        expires_at = min(
            now + timedelta(seconds=self.settings.ttl_seconds),
            absolute_expires_at,
        )
        metadata_secret = self.settings.id_hash_secret.get_secret_value()

        data = SessionCreateDTO(
            stored_session_id=self._hash_session_id(session_id=session_id),
            csrf=csrf,
            absolute_expires_at=absolute_expires_at,
            expires_at=expires_at,
            ip_hash=hash_session_metadata(
                value=source_ip,
                secret=metadata_secret,
            ),
            user_id=user.id,
            user_agent_hash=hash_session_metadata(
                value=user_agent,
                secret=metadata_secret,
            ),
        )
        self.db_session.add(
            BrowserSessionDB(
                id=data.stored_session_id,
                user_id=data.user_id,
                csrf=data.csrf,
                absolute_expires_at=data.absolute_expires_at,
                expires_at=data.expires_at,
                ip_hash=data.ip_hash,
                last_seen_at=now,
                user_agent_hash=data.user_agent_hash,
                created_at=now,
                updated_at=now,
            )
        )
        await self.db_session.flush()
        overflow_ids = (
            select(BrowserSessionDB.id)
            .where(BrowserSessionDB.user_id == user.id)
            .where(BrowserSessionDB.revoked_at.is_(None))
            .where(BrowserSessionDB.id != data.stored_session_id)
            .order_by(
                BrowserSessionDB.created_at.desc(), BrowserSessionDB.public_id.desc()
            )
            .offset(self.settings.max_sessions_per_user - 1)
            .subquery()
        )
        await self.db_session.execute(
            delete(BrowserSessionDB).where(
                BrowserSessionDB.id.in_(select(overflow_ids.c.id))
            )
        )
        await self.db_session.flush()
        logger.info(
            "event=browser_login outcome=attempted subject_id=%s organization_id=%s",
            format_user_id(user.public_id),
            format_organization_id(identity.organization.public_id),
        )
        return LoginResultDTO(session=session_id, csrf=csrf)
