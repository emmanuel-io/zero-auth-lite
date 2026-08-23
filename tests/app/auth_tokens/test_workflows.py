"""Tests for canonical-server auth notification workflows."""

from dataclasses import dataclass
from datetime import datetime, timedelta, UTC

import pytest
from app.auth_tokens.confirmation_service import AuthTokenConfirmationService
from app.auth_tokens.errors import InvalidAuthTokenError
from app.auth_tokens.service import AuthTokenService
from app.auth_tokens.settings import AuthTokenSettings
from app.db.models.auth_token import UserAuthTokenDB
from app.db.models.browser_session import BrowserSessionDB
from app.db.models.oauth2_client import OAuth2ClientDB
from app.db.models.oauth2_session import OAuth2SessionDB
from app.db.models.organization import OrganizationDB
from app.db.models.organization_membership import OrganizationMembershipDB
from app.db.models.user import UserDB, UserEmailDB
from app.events.notifications import AuthNotificationService
from app.events.types import (
    AccountVerificationRequested,
    EmailChangeRequested,
    InviteCreated,
    PasswordResetRequested,
)
from app.identity.users.emails import active_email_loader
from app.identity.users.enums import OrganizationUserRole, UserEmailStatus
from app.mail.schemas import TemplateEmail
from app.public_ids import PublicId
from app.security.session_revocation import SecuritySessionRevocationService
from app.settings.auth import AuthEmailSettings
from fastapi import FastAPI
from sqlalchemy import (
    insert,
    select,
    update as sa_update,
)
from sqlalchemy.ext.asyncio import AsyncSession


pytestmark = pytest.mark.integration

NEW_PASSWORD = "NewPass1!"  # noqa: S105
INVITE_PASSWORD = "InvitePass1!"  # noqa: S105
OLD_PASSWORD_HASH = "old-password-hash"  # noqa: S105
USER_PUBLIC_ID = PublicId(123_456)


@dataclass(slots=True)
class ServiceSessionManager:
    """Service test session and its context manager."""

    db_session: object
    session_manager: object


class FakeMailService:
    """Fake mail service that records templated sends."""

    def __init__(self) -> None:
        """Initialize recorded email storage."""
        self.sent: list[TemplateEmail] = []

    async def send_template(self, email: TemplateEmail) -> None:
        """Record a templated email send."""
        self.sent.append(email)


async def seed_user(
    app: FastAPI, *, verified: bool = False, active: bool = True
) -> int:
    """Create a test user and return its database ID."""
    async with app.state.core_session_factory() as session:
        organization = (
            await session.execute(
                insert(OrganizationDB)
                .values(name="Email Organization")
                .returning(OrganizationDB)
            )
        ).scalar_one()
        user = (
            await session.execute(
                insert(UserDB)
                .values(
                    public_id=int(USER_PUBLIC_ID),
                    first_name="Email",
                    last_name="User",
                    hashed_password=OLD_PASSWORD_HASH,
                    is_active=active,
                )
                .returning(UserDB)
            )
        ).scalar_one()
        session.add(
            UserEmailDB(
                user_id=user.id,
                email="email-user@example.com",
                normalized_email="email-user@example.com",
                status=UserEmailStatus.CURRENT,
                verified_at=datetime.now(UTC) if verified else None,
            )
        )
        session.add(
            OrganizationMembershipDB(
                user_id=user.id,
                organization_id=organization.id,
                role=OrganizationUserRole.MEMBER,
            )
        )
        await session.commit()
        return int(user.id)


async def user_public_id_for_email(app: FastAPI, email: str) -> int:
    """Return the generated public id for a test user."""
    async with app.state.core_session_factory() as session:
        public_id = await session.scalar(
            select(UserDB.public_id)
            .join(UserEmailDB, UserEmailDB.user_id == UserDB.id)
            .where(
                UserEmailDB.normalized_email == email.lower(),
                UserEmailDB.status == UserEmailStatus.CURRENT,
            )
        )
        assert public_id is not None
        return int(public_id)


async def email_id_for_user(
    app: FastAPI,
    user_id: int,
    *,
    status: UserEmailStatus = UserEmailStatus.CURRENT,
) -> int:
    """Return the active email row used by one workflow event."""
    async with app.state.core_session_factory() as session:
        email_id = await session.scalar(
            select(UserEmailDB.id).where(
                UserEmailDB.user_id == user_id,
                UserEmailDB.status == status,
            )
        )
    assert email_id is not None
    return int(email_id)


async def retire_current_email(
    session: AsyncSession, *, user_id: int, replacement: str
) -> None:
    """Retire the current email and create its replacement in a test transaction."""
    now = datetime.now(UTC)
    await session.execute(
        sa_update(UserEmailDB)
        .where(
            UserEmailDB.user_id == user_id,
            UserEmailDB.status == UserEmailStatus.CURRENT,
        )
        .values(status=UserEmailStatus.RETIRED, retired_at=now)
    )
    session.add(
        UserEmailDB(
            user_id=user_id,
            email=replacement,
            normalized_email=replacement.lower(),
            status=UserEmailStatus.CURRENT,
        )
    )


async def build_services(
    app: FastAPI,
) -> tuple[
    AuthNotificationService, AuthTokenConfirmationService, ServiceSessionManager
]:
    """Create app notification and core confirmation services."""
    session_manager = app.state.core_session_factory()
    db_session = await session_manager.__aenter__()
    auth_token_service = AuthTokenService(
        db_session=db_session,
        settings=AuthTokenSettings(),
    )
    notification_service = AuthNotificationService(
        db_session=db_session,
        auth_token_service=auth_token_service,
        settings=AuthEmailSettings(
            frontend_base_url="https://app.example.test",
        ),
    )
    confirmation_service = AuthTokenConfirmationService(
        auth_token_service=auth_token_service,
        db_session=db_session,
        security_revocation=SecuritySessionRevocationService(
            db_session=db_session,
        ),
        password_hasher=app.state.password_hasher,
        session_factory=app.state.core_session_factory,
    )
    return (
        notification_service,
        confirmation_service,
        ServiceSessionManager(
            db_session=db_session,
            session_manager=session_manager,
        ),
    )


async def close_services(session_manager: ServiceSessionManager) -> None:
    """Close the test service session manager."""
    await session_manager.db_session.commit()  # type: ignore[attr-defined]
    await session_manager.session_manager.__aexit__(None, None, None)  # type: ignore[attr-defined]


def token_from_email(email: TemplateEmail, key: str) -> str:
    """Extract a raw token from a sent email context URL."""
    url = str(email.context[key])
    return url.rsplit("token=", maxsplit=1)[1]


async def build_and_send(
    notification: AuthNotificationService,
    mail: FakeMailService,
    event: object,
) -> None:
    """Prepare, commit, and deliver one test notification."""
    message = await notification.build(event)  # type: ignore[arg-type]
    assert message is not None
    await notification.db_session.commit()
    await mail.send_template(message)


@pytest.mark.asyncio
async def test_verification_email_uses_app_mail_and_core_token(
    app: FastAPI,
) -> None:
    """Assert app email delivery is separate from core token confirmation."""
    user_id = await seed_user(app)
    user_email_id = await email_id_for_user(app, user_id)
    mail = FakeMailService()
    notification, confirmation, session_manager = await build_services(app)
    try:
        await build_and_send(
            notification,
            mail,
            AccountVerificationRequested(
                user_public_id=USER_PUBLIC_ID,
                user_email_id=user_email_id,
            ),
        )
        token = token_from_email(mail.sent[0], "verify_url")
        await confirmation.confirm_verification(token)
    finally:
        await close_services(session_manager)

    async with app.state.core_session_factory() as session:
        verified_at = await session.scalar(
            select(UserEmailDB.verified_at).where(UserEmailDB.id == user_email_id)
        )

    assert verified_at is not None
    assert mail.sent[0].template_name == "auth/verify_email.html"
    assert "https://app.example.test/verify-email?token=" in str(
        mail.sent[0].context["verify_url"]
    )


@pytest.mark.asyncio
@pytest.mark.negative
async def test_verification_token_cannot_verify_a_replaced_email(
    app: FastAPI,
) -> None:
    """Reject a link when its original recipient is no longer the user email."""
    user_id = await seed_user(app)
    user_email_id = await email_id_for_user(app, user_id)
    mail = FakeMailService()
    notification, confirmation, session_manager = await build_services(app)
    try:
        await build_and_send(
            notification,
            mail,
            AccountVerificationRequested(
                user_public_id=USER_PUBLIC_ID,
                user_email_id=user_email_id,
            ),
        )
        token = token_from_email(mail.sent[0], "verify_url")
        await retire_current_email(
            confirmation.db_session,
            user_id=user_id,
            replacement="replacement@example.com",
        )
        with pytest.raises(InvalidAuthTokenError):
            await confirmation.confirm_verification(token)
    finally:
        await close_services(session_manager)

    async with app.state.core_session_factory() as session:
        verified_at = await session.scalar(
            select(UserEmailDB.verified_at).where(UserEmailDB.id == user_email_id)
        )

    assert verified_at is None


@pytest.mark.asyncio
@pytest.mark.negative
async def test_delayed_event_cannot_target_a_replaced_email(app: FastAPI) -> None:
    """Discard an event when its account no longer owns the captured address."""
    user_id = await seed_user(app)
    user_email_id = await email_id_for_user(app, user_id)
    notification, _, session_manager = await build_services(app)
    try:
        await retire_current_email(
            notification.db_session,
            user_id=user_id,
            replacement="replacement@example.com",
        )
        message = await notification.build(
            PasswordResetRequested(
                user_public_id=USER_PUBLIC_ID,
                user_email_id=user_email_id,
            )
        )
        token = await notification.db_session.scalar(select(UserAuthTokenDB))
    finally:
        await close_services(session_manager)

    assert message is None
    assert token is None


@pytest.mark.asyncio
@pytest.mark.negative
async def test_password_change_discards_an_older_pending_reset_event(
    app: FastAPI,
) -> None:
    """Do not issue a recovery token requested before a credential change."""
    user_id = await seed_user(app, verified=True)
    user_email_id = await email_id_for_user(app, user_id)
    event = PasswordResetRequested(
        user_public_id=USER_PUBLIC_ID,
        user_email_id=user_email_id,
    )
    notification, _, session_manager = await build_services(app)
    try:
        await notification.db_session.execute(
            sa_update(UserDB)
            .where(UserDB.id == user_id)
            .values(sessions_invalid_before=datetime.now(UTC))
        )
        message = await notification.build(event)
        token = await notification.db_session.scalar(select(UserAuthTokenDB))
    finally:
        await close_services(session_manager)

    assert message is None
    assert token is None


@pytest.mark.asyncio
@pytest.mark.negative
async def test_reset_token_cannot_update_a_replaced_email_identity(
    app: FastAPI,
) -> None:
    """Reject a reset link after its recipient stops identifying the user."""
    user_id = await seed_user(app)
    user_email_id = await email_id_for_user(app, user_id)
    mail = FakeMailService()
    notification, confirmation, session_manager = await build_services(app)
    try:
        await build_and_send(
            notification,
            mail,
            PasswordResetRequested(
                user_public_id=USER_PUBLIC_ID,
                user_email_id=user_email_id,
            ),
        )
        token = token_from_email(mail.sent[0], "reset_url")
        await retire_current_email(
            confirmation.db_session,
            user_id=user_id,
            replacement="replacement@example.com",
        )
        with pytest.raises(InvalidAuthTokenError):
            await confirmation.reset_password(token=token, password=NEW_PASSWORD)
    finally:
        await close_services(session_manager)

    async with app.state.core_session_factory() as session:
        password_hash = await session.scalar(
            select(UserDB.hashed_password).where(UserDB.id == user_id)
        )

    assert password_hash == OLD_PASSWORD_HASH


@pytest.mark.asyncio
@pytest.mark.negative
async def test_inactive_user_does_not_receive_password_reset_token(
    app: FastAPI,
) -> None:
    """Ignore reset requests for inactive accounts without issuing a token."""
    user_id = await seed_user(app, active=False)
    user_email_id = await email_id_for_user(app, user_id)
    notification, _, session_manager = await build_services(app)
    try:
        message = await notification.build(
            PasswordResetRequested(
                user_public_id=USER_PUBLIC_ID,
                user_email_id=user_email_id,
            )
        )
        token = await notification.db_session.scalar(select(UserAuthTokenDB))
    finally:
        await close_services(session_manager)

    assert message is None
    assert token is None


@pytest.mark.asyncio
@pytest.mark.negative
async def test_reset_token_cannot_change_an_inactive_user(app: FastAPI) -> None:
    """Reject a previously issued reset token after account deactivation."""
    user_id = await seed_user(app)
    user_email_id = await email_id_for_user(app, user_id)
    mail = FakeMailService()
    notification, confirmation, session_manager = await build_services(app)
    try:
        await build_and_send(
            notification,
            mail,
            PasswordResetRequested(
                user_public_id=USER_PUBLIC_ID,
                user_email_id=user_email_id,
            ),
        )
        token = token_from_email(mail.sent[0], "reset_url")
        await confirmation.db_session.execute(
            sa_update(UserDB).where(UserDB.id == user_id).values(is_active=False)
        )
        with pytest.raises(InvalidAuthTokenError):
            await confirmation.reset_password(token=token, password=NEW_PASSWORD)
    finally:
        await close_services(session_manager)

    async with app.state.core_session_factory() as session:
        password_hash = await session.scalar(
            select(UserDB.hashed_password).where(UserDB.id == user_id)
        )

    assert password_hash == OLD_PASSWORD_HASH


@pytest.mark.asyncio
@pytest.mark.negative
async def test_token_cannot_be_reused_or_used_for_wrong_purpose(
    app: FastAPI,
) -> None:
    """Assert used and wrong-purpose tokens are rejected."""
    user_id = await seed_user(app)
    user_email_id = await email_id_for_user(app, user_id)
    mail = FakeMailService()
    notification, confirmation, session_manager = await build_services(app)
    try:
        await build_and_send(
            notification,
            mail,
            AccountVerificationRequested(
                user_public_id=USER_PUBLIC_ID,
                user_email_id=user_email_id,
            ),
        )
        token = token_from_email(mail.sent[0], "verify_url")
        with pytest.raises(InvalidAuthTokenError):
            await confirmation.reset_password(token=token, password=NEW_PASSWORD)
        await confirmation.confirm_verification(token)
        with pytest.raises(InvalidAuthTokenError):
            await confirmation.confirm_verification(token)
    finally:
        await close_services(session_manager)


@pytest.mark.asyncio
@pytest.mark.negative
async def test_expired_token_is_rejected(app: FastAPI) -> None:
    """Assert expired tokens cannot be consumed."""
    user_id = await seed_user(app)
    user_email_id = await email_id_for_user(app, user_id)
    mail = FakeMailService()
    notification, confirmation, session_manager = await build_services(app)
    try:
        await build_and_send(
            notification,
            mail,
            AccountVerificationRequested(
                user_public_id=USER_PUBLIC_ID,
                user_email_id=user_email_id,
            ),
        )
        token = token_from_email(mail.sent[0], "verify_url")
        db_session = confirmation.db_session
        await db_session.execute(
            sa_update(UserAuthTokenDB)
            .where(UserAuthTokenDB.user_email_id == user_email_id)
            .values(expires_at=datetime.now(UTC) - timedelta(seconds=1))
        )
        await db_session.commit()
        with pytest.raises(InvalidAuthTokenError):
            await confirmation.confirm_verification(token)
    finally:
        await close_services(session_manager)


@pytest.mark.asyncio
async def test_reset_password_updates_password_and_revokes_sessions(
    app: FastAPI,
) -> None:
    """Reset credentials, verify the recipient email, and revoke sessions."""
    user_id = await seed_user(app, verified=False)
    user_email_id = await email_id_for_user(app, user_id)
    async with app.state.core_session_factory() as session:
        now = datetime.now(UTC)
        organization_id = await session.scalar(
            select(OrganizationMembershipDB.organization_id).where(
                OrganizationMembershipDB.user_id == user_id
            )
        )
        assert organization_id is not None
        await session.execute(
            insert(OAuth2ClientDB).values(
                client_id="auth-workflow-client",
                name="Auth Workflow Client",
                grant_types=["authorization_code"],
                scopes=[],
                is_confidential=False,
                requires_consent=False,
                is_active=True,
            )
        )
        await session.execute(
            insert(BrowserSessionDB).values(
                id="a" * 64,
                csrf="csrf",
                absolute_expires_at=now + timedelta(hours=8),
                expires_at=now + timedelta(hours=1),
                last_seen_at=now,
                user_id=user_id,
            )
        )
        await session.execute(
            insert(OAuth2SessionDB).values(
                client_id="auth-workflow-client",
                grant_type="authorization_code",
                scope="",
                user_id=user_id,
                organization_id=organization_id,
            )
        )
        await session.commit()

    mail = FakeMailService()
    notification, confirmation, session_manager = await build_services(app)
    try:
        await build_and_send(
            notification,
            mail,
            PasswordResetRequested(
                user_public_id=USER_PUBLIC_ID,
                user_email_id=user_email_id,
            ),
        )
        token = token_from_email(mail.sent[0], "reset_url")
        await confirmation.reset_password(token=token, password=NEW_PASSWORD)
    finally:
        await close_services(session_manager)

    async with app.state.core_session_factory() as session:
        user = (
            await session.execute(
                select(UserDB)
                .options(active_email_loader())
                .where(UserDB.id == user_id)
            )
        ).scalar_one()
        revoked_at = await session.scalar(
            select(BrowserSessionDB.revoked_at).where(
                BrowserSessionDB.user_id == user_id
            )
        )
        ended_at = await session.scalar(
            select(OAuth2SessionDB.ended_at).where(OAuth2SessionDB.user_id == user_id)
        )

    assert app.state.password_hasher.verify(
        password=NEW_PASSWORD,
        password_hash=user.hashed_password,
    )
    assert user.email_verified is True
    assert revoked_at is not None
    assert ended_at is not None


@pytest.mark.asyncio
async def test_invite_acceptance_is_application_owned(app: FastAPI) -> None:
    """Assert the canonical server owns invite token application behavior."""
    user_id = await seed_user(app)
    user_email_id = await email_id_for_user(app, user_id)
    user_public_id = await user_public_id_for_email(app, "email-user@example.com")
    mail = FakeMailService()
    notification, confirmation, session_manager = await build_services(app)
    try:
        await build_and_send(
            notification,
            mail,
            InviteCreated(
                user_public_id=user_public_id,
                user_email_id=user_email_id,
            ),
        )
        token = token_from_email(mail.sent[0], "invite_url")
        await confirmation.accept_invite(
            token=token,
            password=INVITE_PASSWORD,
        )
    finally:
        await close_services(session_manager)

    async with app.state.core_session_factory() as session:
        user = (
            await session.execute(
                select(UserDB)
                .options(active_email_loader())
                .where(UserDB.id == user_id)
            )
        ).scalar_one()

    assert app.state.password_hasher.verify(
        password=INVITE_PASSWORD,
        password_hash=user.hashed_password,
    )
    assert user.email_verified is True


@pytest.mark.asyncio
async def test_email_change_token_promotes_pending_email_and_revokes_sessions(
    app: FastAPI,
) -> None:
    """Assert email-change confirmation promotes pending email safely."""
    user_id = await seed_user(app, verified=True)
    user_public_id = await user_public_id_for_email(app, "email-user@example.com")
    async with app.state.core_session_factory() as session:
        now = datetime.now(UTC)
        organization_id = await session.scalar(
            select(OrganizationMembershipDB.organization_id).where(
                OrganizationMembershipDB.user_id == user_id
            )
        )
        assert organization_id is not None
        await session.execute(
            insert(OAuth2ClientDB).values(
                client_id="auth-workflow-client",
                name="Auth Workflow Client",
                grant_types=["authorization_code"],
                scopes=[],
                is_confidential=False,
                requires_consent=False,
                is_active=True,
            )
        )
        pending = (
            await session.execute(
                insert(UserEmailDB)
                .values(
                    user_id=user_id,
                    email="new-email-user@example.com",
                    normalized_email="new-email-user@example.com",
                    status=UserEmailStatus.PENDING,
                )
                .returning(UserEmailDB)
            )
        ).scalar_one()
        await session.execute(
            insert(BrowserSessionDB).values(
                id="b" * 64,
                csrf="csrf",
                absolute_expires_at=now + timedelta(hours=8),
                expires_at=now + timedelta(hours=1),
                last_seen_at=now,
                user_id=user_id,
            )
        )
        await session.execute(
            insert(OAuth2SessionDB).values(
                client_id="auth-workflow-client",
                grant_type="authorization_code",
                scope="",
                user_id=user_id,
                organization_id=organization_id,
            )
        )
        await session.commit()

    mail = FakeMailService()
    notification, confirmation, session_manager = await build_services(app)
    try:
        await build_and_send(
            notification,
            mail,
            EmailChangeRequested(
                user_public_id=user_public_id,
                user_email_id=pending.id,
            ),
        )
        token = token_from_email(mail.sent[0], "verify_url")
        await confirmation.confirm_verification(token)
    finally:
        await close_services(session_manager)

    async with app.state.core_session_factory() as session:
        user = (
            await session.execute(
                select(UserDB)
                .options(active_email_loader())
                .where(UserDB.id == user_id)
            )
        ).scalar_one_or_none()
        revoked_at = await session.scalar(
            select(BrowserSessionDB.revoked_at).where(
                BrowserSessionDB.user_id == user_id
            )
        )
        ended_at = await session.scalar(
            select(OAuth2SessionDB.ended_at).where(OAuth2SessionDB.user_id == user_id)
        )

    assert user is not None
    assert user.email == "new-email-user@example.com"
    assert user.pending_email is None
    assert user.email_verified is True
    assert revoked_at is not None
    assert ended_at is not None
