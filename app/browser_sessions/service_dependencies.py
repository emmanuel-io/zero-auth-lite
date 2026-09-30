"""Dependency providers for browser-session domain services."""

from typing import Annotated

from fastapi import Depends

from app.browser_sessions.authentication import BrowserSessionAuthenticationService
from app.browser_sessions.lifecycle import BrowserSessionLifecycleService
from app.browser_sessions.revocation import BrowserSessionRevocationService
from app.db.dependencies import DbSessionDep, DbSessionFactoryDep
from app.password.dependencies import PasswordHasherDep
from app.settings.dependencies import BrowserSessionSettingsDep


def get_session_authentication_service(
    db_session: DbSessionDep,
    session_settings: BrowserSessionSettingsDep,
    password_hasher: PasswordHasherDep,
    session_factory: DbSessionFactoryDep,
) -> BrowserSessionAuthenticationService:
    """Provide login with request writes and short independent reads."""
    return BrowserSessionAuthenticationService(
        db_session=db_session,
        settings=session_settings,
        password_hasher=password_hasher,
        session_factory=session_factory,
    )


BrowserSessionAuthenticationServiceDep = Annotated[
    BrowserSessionAuthenticationService,
    Depends(get_session_authentication_service),
]


def get_session_lifecycle_service(
    db_session: DbSessionDep,
    session_settings: BrowserSessionSettingsDep,
) -> BrowserSessionLifecycleService:
    """Provide browser-session resolution and expiry behavior."""
    return BrowserSessionLifecycleService(
        db_session=db_session,
        settings=session_settings,
    )


BrowserSessionLifecycleServiceDep = Annotated[
    BrowserSessionLifecycleService,
    Depends(get_session_lifecycle_service),
]


def get_session_revocation_service(
    db_session: DbSessionDep,
    session_settings: BrowserSessionSettingsDep,
) -> BrowserSessionRevocationService:
    """Provide browser-session listing and revocation behavior."""
    return BrowserSessionRevocationService(
        db_session=db_session,
        settings=session_settings,
    )


BrowserSessionRevocationServiceDep = Annotated[
    BrowserSessionRevocationService,
    Depends(get_session_revocation_service),
]
