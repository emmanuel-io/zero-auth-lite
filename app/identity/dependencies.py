"""FastAPI dependency wiring for actor-focused identity services."""

from typing import Annotated

from fastapi import Depends

from app.browser_sessions.dependencies import (
    CurrentBrowserFormUserContextDep,
    CurrentBrowserUserContextDep,
)
from app.db.dependencies import DbSessionDep, DbSessionFactoryDep
from app.identity.services.lifecycle import UserLifecycleService
from app.identity.services.organization_metadata import OrganizationMetadataService
from app.identity.services.organization_users import OrganizationUsersService
from app.identity.services.registration import RegistrationService
from app.identity.services.self import UserSelfService
from app.identity.services.server_organizations import ServerOrganizationsService
from app.identity.services.server_users import ServerUsersService
from app.notifications.dependencies import NotificationPublisherDep
from app.password.dependencies import PasswordHasherDep
from app.security.authentication import CurrentUserContextDep
from app.security.session_revocation_dependencies import SecuritySessionRevocationDep


def get_user_lifecycle_service(
    db_session: DbSessionDep,
    notification_publisher: NotificationPublisherDep,
    password_hasher: PasswordHasherDep,
    security_revocation: SecuritySessionRevocationDep,
    session_factory: DbSessionFactoryDep,
) -> UserLifecycleService:
    """Provide actor-neutral user lifecycle operations."""
    return UserLifecycleService(
        db_session=db_session,
        password_hasher=password_hasher,
        notification_publisher=notification_publisher,
        security_revocation=security_revocation,
        session_factory=session_factory,
    )


UserLifecycleServiceDep = Annotated[
    UserLifecycleService,
    Depends(get_user_lifecycle_service),
]


def get_registration_service(
    db_session: DbSessionDep,
    notification_publisher: NotificationPublisherDep,
    password_hasher: PasswordHasherDep,
) -> RegistrationService:
    """Provide the canonical self-registration lifecycle."""
    return RegistrationService(
        db_session=db_session,
        notification_publisher=notification_publisher,
        password_hasher=password_hasher,
    )


RegistrationServiceDep = Annotated[
    RegistrationService,
    Depends(get_registration_service),
]


def get_user_self_service(
    db_session: DbSessionDep,
    user_ctx: CurrentUserContextDep,
    lifecycle: UserLifecycleServiceDep,
) -> UserSelfService:
    """Provide current-user profile and account operations."""
    return UserSelfService(
        db_session=db_session,
        user_ctx=user_ctx,
        lifecycle=lifecycle,
    )


UserSelfServiceDep = Annotated[UserSelfService, Depends(get_user_self_service)]


def get_browser_user_self_service(
    db_session: DbSessionDep,
    user_ctx: CurrentBrowserUserContextDep,
    lifecycle: UserLifecycleServiceDep,
) -> UserSelfService:
    """Provide self-service bound specifically to a browser identity."""
    return UserSelfService(
        db_session=db_session,
        user_ctx=user_ctx,
        lifecycle=lifecycle,
    )


BrowserUserSelfServiceDep = Annotated[
    UserSelfService,
    Depends(get_browser_user_self_service),
]


def get_browser_form_user_self_service(
    db_session: DbSessionDep,
    user_ctx: CurrentBrowserFormUserContextDep,
    lifecycle: UserLifecycleServiceDep,
) -> UserSelfService:
    """Provide CSRF-validated self-service for a browser form mutation."""
    return UserSelfService(
        db_session=db_session,
        user_ctx=user_ctx,
        lifecycle=lifecycle,
    )


BrowserFormUserSelfServiceDep = Annotated[
    UserSelfService,
    Depends(get_browser_form_user_self_service),
]


def get_organization_users_service(
    db_session: DbSessionDep,
    user_ctx: CurrentUserContextDep,
    lifecycle: UserLifecycleServiceDep,
) -> OrganizationUsersService:
    """Provide organization-scoped identity administration."""
    return OrganizationUsersService(
        db_session=db_session,
        actor_ctx=user_ctx,
        lifecycle=lifecycle,
    )


OrganizationUsersServiceDep = Annotated[
    OrganizationUsersService,
    Depends(get_organization_users_service),
]


def get_organization_metadata_service(
    db_session: DbSessionDep,
    user_ctx: CurrentUserContextDep,
) -> OrganizationMetadataService:
    """Provide organization-scoped metadata administration."""
    return OrganizationMetadataService(db_session=db_session, actor_ctx=user_ctx)


OrganizationMetadataServiceDep = Annotated[
    OrganizationMetadataService,
    Depends(get_organization_metadata_service),
]


def get_server_users_service(
    db_session: DbSessionDep,
    user_ctx: CurrentUserContextDep,
    lifecycle: UserLifecycleServiceDep,
) -> ServerUsersService:
    """Provide server-operator identity administration."""
    return ServerUsersService(
        db_session=db_session,
        actor_ctx=user_ctx,
        lifecycle=lifecycle,
    )


ServerUsersServiceDep = Annotated[
    ServerUsersService,
    Depends(get_server_users_service),
]


def get_server_organizations_service(
    db_session: DbSessionDep,
    user_ctx: CurrentUserContextDep,
) -> ServerOrganizationsService:
    """Provide server-operator organization administration."""
    return ServerOrganizationsService(db_session=db_session, actor_ctx=user_ctx)


ServerOrganizationsServiceDep = Annotated[
    ServerOrganizationsService,
    Depends(get_server_organizations_service),
]
