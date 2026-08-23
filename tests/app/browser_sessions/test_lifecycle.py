"""Tests for browser-session authentication and lifecycle behavior."""

from datetime import datetime, timedelta, UTC

import app.browser_sessions.authentication as browser_authentication
import pytest
from app.browser_sessions.authentication import SessionAuthenticationService
from app.browser_sessions.dtos import (
    SessionCreateDTO,
    SessionReadDTO,
)
from app.browser_sessions.errors import (
    InvalidLoginCredentialsError,
    SessionInvalidError,
)
from app.browser_sessions.hashing import hash_session_id, hash_session_metadata
from app.browser_sessions.lifecycle import SessionLifecycleService
from app.browser_sessions.revocation import SessionRevocationService
from app.browser_sessions.settings import SessionSettings
from app.db.models.browser_session import BrowserSessionDB
from app.db.models.user import UserDB, UserEmailDB
from app.identity.users.enums import UserEmailStatus
from app.password.pwdlib_hasher import PwdlibPasswordHasher
from sqlalchemy import select, update

from tests.fixtures.auth import UserCredentials
from tests.fixtures.session import BrowserSessionFixture


pytestmark = pytest.mark.integration

SESSION_ID_HASH_SECRET = "test-session-id-hash-secret-with-more-than-32-bytes"  # noqa: S105
EXPECTED_MANAGED_SESSION_COUNT = 2
PASSWORD_HASHER = PwdlibPasswordHasher()


def session_create(
    *,
    session_id: str,
    user_id: int,
    csrf: str,
    expires_at: datetime,
) -> SessionCreateDTO:
    """Return a complete session creation DTO for service tests."""
    return SessionCreateDTO(
        stored_session_id=session_id,
        user_id=user_id,
        csrf=csrf,
        absolute_expires_at=datetime.now(UTC) + timedelta(hours=8),
        expires_at=expires_at,
    )


def stored_session_id(raw_session_id: str) -> str:
    """Return the stored digest for a test session ID."""
    return hash_session_id(
        session_id=raw_session_id,
        secret=SESSION_ID_HASH_SECRET,
    )


def auth_service_for(
    session_fixture: BrowserSessionFixture,
) -> SessionAuthenticationService:
    """Return an auth service with test settings."""
    return SessionAuthenticationService(
        password_hasher=PASSWORD_HASHER,
        db_session=session_fixture.db_session,
        session_factory=session_fixture.session_factory,
        settings=SessionSettings(id_hash_secret=SESSION_ID_HASH_SECRET),
    )


def lifecycle_service_for(
    session_fixture: BrowserSessionFixture,
) -> SessionLifecycleService:
    """Return a session lifecycle service with test settings."""
    return SessionLifecycleService(
        db_session=session_fixture.db_session,
        settings=SessionSettings(id_hash_secret=SESSION_ID_HASH_SECRET),
    )


async def load_and_slide(
    service: SessionLifecycleService,
    *,
    session_id: str,
) -> tuple[SessionReadDTO, bool]:
    """Exercise explicit validation followed by lifecycle sliding."""
    session = await service.load_session(session_id=session_id)
    result = await service.slide_session(session=session)
    return result.session, result.expiry_extended


def revocation_service_for(
    session_fixture: BrowserSessionFixture,
) -> SessionRevocationService:
    """Return a session revocation service with test settings."""
    return SessionRevocationService(
        db_session=session_fixture.db_session,
        settings=SessionSettings(id_hash_secret=SESSION_ID_HASH_SECRET),
    )


@pytest.mark.asyncio
async def test_login_uses_injected_session_ttl(
    session_fixture: BrowserSessionFixture,
    verified_user_credentials: UserCredentials,
) -> None:
    """Assert login session expiry is derived from injected settings."""
    session_settings = SessionSettings(
        id_hash_secret=SESSION_ID_HASH_SECRET,
        ttl_seconds=123,
        slide_seconds=60,
    )
    auth_service = SessionAuthenticationService(
        password_hasher=PASSWORD_HASHER,
        db_session=session_fixture.db_session,
        session_factory=session_fixture.session_factory,
        settings=session_settings,
    )
    before_login = datetime.now(UTC)

    login = await auth_service.login(
        email=verified_user_credentials.email,
        password=verified_user_credentials.password,
    )

    persisted_session = await session_fixture.read(
        session_id=stored_session_id(login.session)
    )

    assert persisted_session is not None
    assert persisted_session.created_at >= before_login
    assert persisted_session.expires_at >= before_login + timedelta(seconds=123)
    assert persisted_session.expires_at <= datetime.now(UTC) + timedelta(seconds=123)


@pytest.mark.asyncio
async def test_login_rejects_a_password_changed_during_verification(
    session_fixture: BrowserSessionFixture,
    verified_user_credentials: UserCredentials,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Do not create a session from credentials invalidated concurrently."""

    async def change_password_then_accept(
        _password_hasher: object,
        *,
        password: str,
        password_hash: str,
    ) -> bool:
        _ = password, password_hash
        async with session_fixture.session_factory.begin() as concurrent_session:
            await concurrent_session.execute(
                update(UserDB)
                .where(
                    UserDB.id
                    == select(UserEmailDB.user_id)
                    .where(
                        UserEmailDB.normalized_email
                        == verified_user_credentials.email.lower(),
                        UserEmailDB.status == UserEmailStatus.CURRENT,
                    )
                    .scalar_subquery()
                )
                .values(
                    hashed_password="concurrently-changed-password-hash"  # noqa: S106
                )
            )
        return True

    monkeypatch.setattr(
        browser_authentication,
        "verify_password",
        change_password_then_accept,
    )

    with pytest.raises(InvalidLoginCredentialsError):
        await auth_service_for(session_fixture).login(
            email=verified_user_credentials.email,
            password=verified_user_credentials.password,
        )

    session_id = await session_fixture.db_session.scalar(select(BrowserSessionDB.id))
    assert session_id is None


@pytest.mark.asyncio
async def test_login_hashes_optional_metadata(
    session_fixture: BrowserSessionFixture,
    verified_user_credentials: UserCredentials,
) -> None:
    """Assert login stores hashed source IP and user-agent metadata."""
    auth_service = auth_service_for(session_fixture)
    source_ip = "203.0.113.10"
    user_agent = "UnitTest/1.0"

    login = await auth_service.login(
        email=verified_user_credentials.email,
        password=verified_user_credentials.password,
        source_ip=source_ip,
        user_agent=user_agent,
    )

    persisted_session = await session_fixture.read(
        session_id=stored_session_id(login.session)
    )

    assert persisted_session is not None
    assert persisted_session.ip_hash == hash_session_metadata(
        value=source_ip,
        secret=SESSION_ID_HASH_SECRET,
    )
    assert persisted_session.user_agent_hash == hash_session_metadata(
        value=user_agent,
        secret=SESSION_ID_HASH_SECRET,
    )


@pytest.mark.asyncio
async def test_login_session_limit_preserves_new_session(
    session_fixture: BrowserSessionFixture,
    verified_user_credentials: UserCredentials,
) -> None:
    """Keep the session returned to the browser when enforcing the limit."""
    auth_service = SessionAuthenticationService(
        password_hasher=PASSWORD_HASHER,
        db_session=session_fixture.db_session,
        session_factory=session_fixture.session_factory,
        settings=SessionSettings(
            id_hash_secret=SESSION_ID_HASH_SECRET,
            max_sessions_per_user=1,
        ),
    )
    first = await auth_service.login(
        email=verified_user_credentials.email,
        password=verified_user_credentials.password,
    )
    second = await auth_service.login(
        email=verified_user_credentials.email,
        password=verified_user_credentials.password,
    )

    session_ids = list(
        await session_fixture.db_session.scalars(
            select(BrowserSessionDB.id)
            .join(UserEmailDB, UserEmailDB.user_id == BrowserSessionDB.user_id)
            .where(
                UserEmailDB.normalized_email == verified_user_credentials.email.lower(),
                UserEmailDB.status == UserEmailStatus.CURRENT,
            )
        )
    )

    assert stored_session_id(first.session) not in session_ids
    assert session_ids == [stored_session_id(second.session)]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("email", "password"),
    [
        ("missing@example.com", "S3cretPass1"),
        ("admin@example.com", "wrong-password"),
    ],
)
@pytest.mark.negative
async def test_login_rejects_missing_user_and_bad_password(
    session_fixture: BrowserSessionFixture,
    verified_user_credentials: UserCredentials,
    email: str,
    password: str,
) -> None:
    """Assert invalid credentials are rejected."""
    _ = verified_user_credentials
    auth_service = auth_service_for(session_fixture)

    with pytest.raises(InvalidLoginCredentialsError):
        await auth_service.login(email=email, password=password)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("column", "value"),
    [
        ("is_active", False),
        ("email_verified", False),
    ],
)
@pytest.mark.negative
async def test_login_rejects_inactive_or_unverified_users(
    session_fixture: BrowserSessionFixture,
    verified_user_credentials: UserCredentials,
    column: str,
    value: bool,  # noqa: FBT001
) -> None:
    """Assert inactive and unverified users cannot log in."""
    if column == "email_verified":
        await session_fixture.db_session.execute(
            update(UserEmailDB)
            .where(
                UserEmailDB.normalized_email == verified_user_credentials.email.lower(),
                UserEmailDB.status == UserEmailStatus.CURRENT,
            )
            .values(verified_at=None)
        )
    else:
        await session_fixture.db_session.execute(
            update(UserDB)
            .where(
                UserDB.id
                == select(UserEmailDB.user_id)
                .where(
                    UserEmailDB.normalized_email
                    == verified_user_credentials.email.lower(),
                    UserEmailDB.status == UserEmailStatus.CURRENT,
                )
                .scalar_subquery()
            )
            .values({column: value})
        )
    await session_fixture.db_session.commit()
    auth_service = auth_service_for(session_fixture)

    with pytest.raises(InvalidLoginCredentialsError):
        await auth_service.login(
            email=verified_user_credentials.email,
            password=verified_user_credentials.password,
        )


@pytest.mark.asyncio
async def test_load_and_slide_session_uses_injected_settings(
    session_fixture: BrowserSessionFixture,
    session_store_user_id: int,
) -> None:
    """Assert sliding expiry uses injected slide and TTL settings."""
    session_settings = SessionSettings(
        id_hash_secret=SESSION_ID_HASH_SECRET,
        ttl_seconds=300,
        slide_seconds=120,
    )
    auth_service = SessionLifecycleService(
        db_session=session_fixture.db_session,
        settings=session_settings,
    )
    session_id = "settings-slide-session"
    stored_id = stored_session_id(session_id)
    csrf_value = "csrf-token"
    old_expires_at = datetime.now(UTC) + timedelta(seconds=90)

    await session_fixture.create(
        dto=session_create(
            session_id=stored_id,
            user_id=session_store_user_id,
            csrf=csrf_value,
            expires_at=old_expires_at,
        )
    )
    before_slide = datetime.now(UTC)

    session_data, expiry_extended = await load_and_slide(
        auth_service,
        session_id=session_id,
    )

    patched_session = await session_fixture.read(session_id=stored_id)

    assert session_data.user_id == session_store_user_id
    assert expiry_extended is True
    assert patched_session is not None
    assert session_data.expires_at == patched_session.expires_at
    assert patched_session.expires_at >= before_slide + timedelta(seconds=300)
    assert patched_session.expires_at <= datetime.now(UTC) + timedelta(seconds=300)
    assert patched_session.last_seen_at >= before_slide

    await session_fixture.revoke(session_id=stored_id, reason="test_cleanup")


@pytest.mark.asyncio
async def test_load_and_slide_session_skips_patch_before_slide_window(
    session_fixture: BrowserSessionFixture,
    session_store_user_id: int,
) -> None:
    """Assert sessions outside the slide window keep their original expiry."""
    session_settings = SessionSettings(
        id_hash_secret=SESSION_ID_HASH_SECRET,
        ttl_seconds=300,
        slide_seconds=120,
    )
    auth_service = SessionLifecycleService(
        db_session=session_fixture.db_session,
        settings=session_settings,
    )
    session_id = "settings-no-slide-session"
    stored_id = stored_session_id(session_id)
    csrf_value = "csrf-token"
    expires_at = datetime.now(UTC) + timedelta(seconds=180)

    await session_fixture.create(
        dto=session_create(
            session_id=stored_id,
            user_id=session_store_user_id,
            csrf=csrf_value,
            expires_at=expires_at,
        )
    )
    persisted_before = await session_fixture.read(session_id=stored_id)
    assert persisted_before is not None

    session_data, expiry_extended = await load_and_slide(
        auth_service,
        session_id=session_id,
    )

    persisted_session = await session_fixture.read(session_id=stored_id)

    assert session_data.user_id == session_store_user_id
    assert expiry_extended is False
    assert persisted_session is not None
    assert session_data.expires_at == expires_at
    assert session_data.last_seen_at == persisted_before.last_seen_at
    assert persisted_session.expires_at == expires_at
    assert persisted_session.last_seen_at == persisted_before.last_seen_at

    await session_fixture.revoke(session_id=stored_id, reason="test_cleanup")


@pytest.mark.asyncio
async def test_load_and_slide_session_skips_noop_at_absolute_expiry(
    session_fixture: BrowserSessionFixture,
    session_store_user_id: int,
) -> None:
    """Avoid repeated writes when absolute expiry prevents a slide."""
    session_settings = SessionSettings(
        id_hash_secret=SESSION_ID_HASH_SECRET,
        ttl_seconds=300,
        absolute_ttl_seconds=300,
        slide_seconds=120,
    )
    auth_service = SessionLifecycleService(
        db_session=session_fixture.db_session,
        settings=session_settings,
    )
    session_id = "settings-absolute-expiry-session"
    stored_id = stored_session_id(session_id)
    csrf_value = "csrf-token"
    expires_at = datetime.now(UTC) + timedelta(seconds=90)
    await session_fixture.create(
        dto=session_create(
            session_id=stored_id,
            user_id=session_store_user_id,
            csrf=csrf_value,
            expires_at=expires_at,
        )
    )
    await session_fixture.db_session.execute(
        update(BrowserSessionDB)
        .where(BrowserSessionDB.id == stored_id)
        .values(absolute_expires_at=expires_at)
    )
    await session_fixture.db_session.flush()
    persisted_before = await session_fixture.read(session_id=stored_id)
    assert persisted_before is not None

    session_data, expiry_extended = await load_and_slide(
        auth_service,
        session_id=session_id,
    )

    persisted_session = await session_fixture.read(session_id=stored_id)
    assert persisted_session is not None
    assert expiry_extended is False
    assert session_data.expires_at == persisted_before.expires_at
    assert session_data.last_seen_at == persisted_before.last_seen_at
    assert persisted_session.expires_at == persisted_before.expires_at
    assert persisted_session.last_seen_at == persisted_before.last_seen_at

    await session_fixture.revoke(session_id=stored_id, reason="test_cleanup")


@pytest.mark.asyncio
async def test_load_and_slide_session_records_stale_activity_without_sliding(
    session_fixture: BrowserSessionFixture,
    session_store_user_id: int,
) -> None:
    """Throttle activity writes independently from expiry sliding."""
    session_settings = SessionSettings(
        id_hash_secret=SESSION_ID_HASH_SECRET,
        ttl_seconds=300,
        slide_seconds=120,
    )
    auth_service = SessionLifecycleService(
        db_session=session_fixture.db_session,
        settings=session_settings,
    )
    session_id = "settings-stale-activity-session"
    stored_id = stored_session_id(session_id)
    csrf_value = "csrf-token"
    expires_at = datetime.now(UTC) + timedelta(seconds=240)
    stale_last_seen_at = datetime.now(UTC) - timedelta(seconds=180)
    await session_fixture.create(
        dto=session_create(
            session_id=stored_id,
            user_id=session_store_user_id,
            csrf=csrf_value,
            expires_at=expires_at,
        )
    )
    await session_fixture.db_session.execute(
        update(BrowserSessionDB)
        .where(BrowserSessionDB.id == stored_id)
        .values(last_seen_at=stale_last_seen_at)
    )
    await session_fixture.db_session.flush()
    before_load = datetime.now(UTC)

    session_data, expiry_extended = await load_and_slide(
        auth_service,
        session_id=session_id,
    )

    persisted_session = await session_fixture.read(session_id=stored_id)
    assert persisted_session is not None
    assert expiry_extended is False
    assert session_data.expires_at == expires_at
    assert persisted_session.expires_at == expires_at
    assert session_data.last_seen_at >= before_load
    assert persisted_session.last_seen_at >= before_load

    await session_fixture.revoke(session_id=stored_id, reason="test_cleanup")


@pytest.mark.asyncio
async def test_session_management_methods_delegate_to_store(
    session_fixture: BrowserSessionFixture,
    session_store_user_id: int,
) -> None:
    """Assert logout, list, revoke-all, and cleanup persistence behavior."""
    auth_service = revocation_service_for(session_fixture)
    session_id = "management-session"
    stored_id = stored_session_id(session_id)
    expired_session_id = "expired-management-session"
    expired_stored_id = stored_session_id(expired_session_id)
    await session_fixture.create(
        dto=session_create(
            session_id=stored_id,
            user_id=session_store_user_id,
            csrf="csrf-token",
            expires_at=datetime.now(UTC) + timedelta(minutes=5),
        )
    )
    await session_fixture.create(
        dto=session_create(
            session_id=expired_stored_id,
            user_id=session_store_user_id,
            csrf="csrf-token",
            expires_at=datetime.now(UTC) - timedelta(minutes=5),
        )
    )

    sessions = await auth_service.list_user_sessions(
        user_id=session_store_user_id,
        active_only=False,
        limit=10,
    )
    revoked_one = await auth_service.logout(session_id=session_id)
    revoked_by_public_id = await auth_service.revoke_user_session_by_public_id(
        public_id=sessions[0].public_id,
        user_id=session_store_user_id,
        reason="unit_test",
    )
    missing_public_id_revoked = await auth_service.revoke_user_session_by_public_id(
        public_id=999999,
        user_id=session_store_user_id,
    )
    revoked_all = await auth_service.revoke_user_sessions(user_id=session_store_user_id)
    cleaned = await auth_service.cleanup_expired_sessions()

    assert len(sessions) == EXPECTED_MANAGED_SESSION_COUNT
    assert revoked_one is True
    assert revoked_by_public_id is True
    assert missing_public_id_revoked is False
    assert revoked_all >= 0
    assert cleaned >= 1


@pytest.mark.asyncio
async def test_cleanup_expired_sessions_respects_batch_size(
    session_fixture: BrowserSessionFixture,
    session_store_user_id: int,
) -> None:
    """Delete no more than the configured cleanup batch in one transaction."""
    for suffix in ("one", "two"):
        await session_fixture.create(
            dto=session_create(
                session_id=stored_session_id(f"expired-{suffix}"),
                user_id=session_store_user_id,
                csrf="csrf-token",
                expires_at=datetime.now(UTC) - timedelta(minutes=5),
            )
        )
    service = SessionRevocationService(
        db_session=session_fixture.db_session,
        settings=SessionSettings(
            id_hash_secret=SESSION_ID_HASH_SECRET,
            cleanup_batch_size=1,
        ),
    )

    assert await service.cleanup_expired_sessions() == 1
    assert await service.cleanup_expired_sessions() == 1


@pytest.mark.asyncio
async def test_get_session_csrf_returns_token_for_valid_session(
    session_fixture: BrowserSessionFixture,
    session_store_user_id: int,
) -> None:
    """Assert a valid raw session ID resolves its CSRF token."""
    auth_service = SessionLifecycleService(
        db_session=session_fixture.db_session,
        settings=SessionSettings(id_hash_secret=SESSION_ID_HASH_SECRET),
    )
    session_id = "csrf-valid-session"
    csrf_value = "csrf-token"
    await session_fixture.create(
        dto=session_create(
            session_id=stored_session_id(session_id),
            user_id=session_store_user_id,
            csrf=csrf_value,
            expires_at=datetime.now(UTC) + timedelta(minutes=5),
        )
    )

    assert await auth_service.get_session_csrf(session_id=session_id) == csrf_value


@pytest.mark.asyncio
@pytest.mark.negative
async def test_get_session_csrf_rejects_missing_session(
    session_fixture: BrowserSessionFixture,
) -> None:
    """Assert missing sessions cannot expose CSRF tokens."""
    auth_service = SessionLifecycleService(
        db_session=session_fixture.db_session,
        settings=SessionSettings(id_hash_secret=SESSION_ID_HASH_SECRET),
    )

    with pytest.raises(SessionInvalidError):
        await auth_service.get_session_csrf(session_id="missing-session")


@pytest.mark.asyncio
@pytest.mark.negative
async def test_get_session_csrf_rejects_revoked_session(
    session_fixture: BrowserSessionFixture,
    session_store_user_id: int,
) -> None:
    """Assert revoked sessions cannot expose CSRF tokens."""
    auth_service = SessionLifecycleService(
        db_session=session_fixture.db_session,
        settings=SessionSettings(id_hash_secret=SESSION_ID_HASH_SECRET),
    )
    session_id = "csrf-revoked-session"
    stored_id = stored_session_id(session_id)
    await session_fixture.create(
        dto=session_create(
            session_id=stored_id,
            user_id=session_store_user_id,
            csrf="csrf-token",
            expires_at=datetime.now(UTC) + timedelta(minutes=5),
        )
    )
    await session_fixture.revoke(session_id=stored_id, reason="test")

    with pytest.raises(SessionInvalidError):
        await auth_service.get_session_csrf(session_id=session_id)


@pytest.mark.asyncio
@pytest.mark.negative
async def test_get_session_csrf_rejects_expired_session(
    session_fixture: BrowserSessionFixture,
    session_store_user_id: int,
) -> None:
    """Assert expired sessions cannot expose CSRF tokens."""
    auth_service = SessionLifecycleService(
        db_session=session_fixture.db_session,
        settings=SessionSettings(id_hash_secret=SESSION_ID_HASH_SECRET),
    )
    session_id = "csrf-expired-session"
    await session_fixture.create(
        dto=session_create(
            session_id=stored_session_id(session_id),
            user_id=session_store_user_id,
            csrf="csrf-token",
            expires_at=datetime.now(UTC) - timedelta(seconds=1),
        )
    )

    with pytest.raises(SessionInvalidError):
        await auth_service.get_session_csrf(session_id=session_id)


@pytest.mark.asyncio
@pytest.mark.negative
async def test_load_and_slide_session_rejects_missing_session(
    session_fixture: BrowserSessionFixture,
) -> None:
    """Assert missing browser sessions cannot be loaded."""
    auth_service = lifecycle_service_for(session_fixture)

    with pytest.raises(SessionInvalidError):
        await load_and_slide(
            auth_service,
            session_id="missing-session",
        )


@pytest.mark.asyncio
@pytest.mark.negative
async def test_load_and_slide_session_rejects_revoked_or_expired_session(
    session_fixture: BrowserSessionFixture,
    session_store_user_id: int,
) -> None:
    """Assert revoked and expired browser sessions cannot be loaded."""
    auth_service = lifecycle_service_for(session_fixture)
    revoked_session_id = "load-revoked-session"
    expired_session_id = "load-expired-session"
    await session_fixture.create(
        dto=session_create(
            session_id=stored_session_id(revoked_session_id),
            user_id=session_store_user_id,
            csrf="csrf-token",
            expires_at=datetime.now(UTC) + timedelta(minutes=5),
        )
    )
    await session_fixture.revoke(
        session_id=stored_session_id(revoked_session_id),
        reason="test",
    )
    await session_fixture.create(
        dto=session_create(
            session_id=stored_session_id(expired_session_id),
            user_id=session_store_user_id,
            csrf="csrf-token",
            expires_at=datetime.now(UTC) - timedelta(seconds=1),
        )
    )

    with pytest.raises(SessionInvalidError):
        await load_and_slide(
            auth_service,
            session_id=revoked_session_id,
        )
    with pytest.raises(SessionInvalidError):
        await load_and_slide(
            auth_service,
            session_id=expired_session_id,
        )


def test_session_dtos_reject_naive_datetimes() -> None:
    """Assert session DTOs reject timezone-naive datetime values."""
    naive_now = datetime(2026, 1, 1)  # noqa: DTZ001

    with pytest.raises(ValueError):  # noqa: PT011
        SessionCreateDTO(
            stored_session_id="session",
            user_id=1,
            csrf="csrf-token",
            absolute_expires_at=naive_now,
            expires_at=datetime.now(UTC),
        )
