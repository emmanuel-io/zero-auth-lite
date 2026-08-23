"""Tests for focused browser-session service dependencies."""

from typing import cast, TYPE_CHECKING

import pytest
from app.browser_sessions.authentication import SessionAuthenticationService
from app.browser_sessions.dependencies import (
    get_session_authentication_service,
    get_session_lifecycle_service,
    get_session_revocation_service,
)
from app.browser_sessions.lifecycle import SessionLifecycleService
from app.browser_sessions.revocation import SessionRevocationService
from app.browser_sessions.settings import SessionSettings


pytestmark = pytest.mark.unit

if TYPE_CHECKING:
    from app.password.protocols import PasswordHasherProtocol
    from sqlalchemy.ext.asyncio import async_sessionmaker, AsyncSession

DB_SESSION = cast("AsyncSession", object())
SESSION_FACTORY = cast("async_sessionmaker[AsyncSession]", object())
PASSWORD_HASHER = cast("PasswordHasherProtocol", object())
SESSION_SETTINGS = SessionSettings()


def test_session_dependencies_build_focused_services() -> None:
    """Assert each FastAPI dependency constructs one focused service."""
    authentication = get_session_authentication_service(
        DB_SESSION,
        SESSION_SETTINGS,
        PASSWORD_HASHER,
        SESSION_FACTORY,
    )
    lifecycle = get_session_lifecycle_service(
        DB_SESSION,
        SESSION_SETTINGS,
    )
    revocation = get_session_revocation_service(
        DB_SESSION,
        SESSION_SETTINGS,
    )

    assert isinstance(authentication, SessionAuthenticationService)
    assert isinstance(lifecycle, SessionLifecycleService)
    assert isinstance(revocation, SessionRevocationService)
