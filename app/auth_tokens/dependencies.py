"""Dependency injection for single-use authentication tokens."""

from typing import Annotated

from fastapi import Depends

from app.auth_tokens.confirmation_service import AuthTokenConfirmationService
from app.auth_tokens.service import AuthTokenService
from app.db.dependencies import DbSessionDep, DbSessionFactoryDep
from app.password.dependencies import PasswordHasherDep
from app.security.session_revocation_dependencies import SecuritySessionRevocationDep
from app.settings.dependencies import AuthTokenSettingsDep


def get_auth_token_service(
    db_session: DbSessionDep,
    settings: AuthTokenSettingsDep,
) -> AuthTokenService:
    """Provide the single-use auth token service."""
    return AuthTokenService(
        db_session=db_session,
        settings=settings,
    )


AuthTokenServiceDep = Annotated[AuthTokenService, Depends(get_auth_token_service)]


def get_auth_token_confirmation_service(
    auth_token_service: AuthTokenServiceDep,
    db_session: DbSessionDep,
    security_revocation: SecuritySessionRevocationDep,
    password_hasher: PasswordHasherDep,
    session_factory: DbSessionFactoryDep,
) -> AuthTokenConfirmationService:
    """Build the app-owned auth token confirmation service."""
    return AuthTokenConfirmationService(
        auth_token_service=auth_token_service,
        db_session=db_session,
        security_revocation=security_revocation,
        password_hasher=password_hasher,
        session_factory=session_factory,
    )


AuthTokenConfirmationServiceDep = Annotated[
    AuthTokenConfirmationService,
    Depends(get_auth_token_confirmation_service),
]
