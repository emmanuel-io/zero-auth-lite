"""Tests for focused browser-session service dependencies."""

from typing import cast, TYPE_CHECKING

import pytest
from app.browser_sessions.authentication import BrowserSessionAuthenticationService
from app.browser_sessions.lifecycle import BrowserSessionLifecycleService
from app.browser_sessions.revocation import BrowserSessionRevocationService
from app.browser_sessions.service_dependencies import (
    get_session_authentication_service,
    get_session_lifecycle_service,
    get_session_revocation_service,
)
from app.browser_sessions.settings import BrowserSessionSettings


pytestmark = pytest.mark.unit

if TYPE_CHECKING:
    from app.password.protocols import PasswordHasherProtocol
    from sqlalchemy.ext.asyncio import async_sessionmaker, AsyncSession

DB_SESSION = cast("AsyncSession", object())
SESSION_FACTORY = cast("async_sessionmaker[AsyncSession]", object())
PASSWORD_HASHER = cast("PasswordHasherProtocol", object())
SESSION_SETTINGS = BrowserSessionSettings()


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

    assert isinstance(authentication, BrowserSessionAuthenticationService)
    assert isinstance(lifecycle, BrowserSessionLifecycleService)
    assert isinstance(revocation, BrowserSessionRevocationService)
