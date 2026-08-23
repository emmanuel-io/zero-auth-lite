"""FastAPI dependency wiring for actor-focused identity services."""

from typing import Annotated

from fastapi import Depends

from app.browser_sessions.dependencies import CurrentBrowserUserContextDep
from app.db.dependencies import DbSessionDep, DbSessionFactoryDep
from app.events.dependencies import EventPublisherDep
from app.identity.services.lifecycle import UserLifecycleService
from app.identity.services.operator import OperatorUsersService
from app.identity.services.operator_organizations import OperatorOrganizationsService
from app.identity.services.organization import OrganizationUsersService
from app.identity.services.organization_metadata import OrganizationMetadataService
from app.identity.services.self import UserSelfService
from app.password.dependencies import PasswordHasherDep
from app.security.authentication import CurrentUserContextDep
from app.security.session_revocation_dependencies import SecuritySessionRevocationDep


def get_user_lifecycle_service(
    db_session: DbSessionDep,
    event_publisher: EventPublisherDep,
    password_hasher: PasswordHasherDep,
    security_revocation: SecuritySessionRevocationDep,
    session_factory: DbSessionFactoryDep,
) -> UserLifecycleService:
    """Provide actor-neutral user lifecycle operations."""
    return UserLifecycleService(
        db_session=db_session,
        password_hasher=password_hasher,
        event_publisher=event_publisher,
        security_revocation=security_revocation,
        session_factory=session_factory,
    )


UserLifecycleServiceDep = Annotated[
    UserLifecycleService,
    Depends(get_user_lifecycle_service),
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


def get_organization_users_service(
    db_session: DbSessionDep,
    user_ctx: CurrentUserContextDep,
    lifecycle: UserLifecycleServiceDep,
) -> OrganizationUsersService:
    """Provide organization-scoped identity administration."""
    return OrganizationUsersService(
        db_session=db_session,
        user_ctx=user_ctx,
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
    return OrganizationMetadataService(db_session=db_session, user_ctx=user_ctx)


OrganizationMetadataServiceDep = Annotated[
    OrganizationMetadataService,
    Depends(get_organization_metadata_service),
]


def get_operator_users_service(
    db_session: DbSessionDep,
    user_ctx: CurrentUserContextDep,
    lifecycle: UserLifecycleServiceDep,
) -> OperatorUsersService:
    """Provide server-operator identity administration."""
    return OperatorUsersService(
        db_session=db_session,
        user_ctx=user_ctx,
        lifecycle=lifecycle,
    )


OperatorUsersServiceDep = Annotated[
    OperatorUsersService,
    Depends(get_operator_users_service),
]


def get_operator_organizations_service(
    db_session: DbSessionDep,
    user_ctx: CurrentUserContextDep,
) -> OperatorOrganizationsService:
    """Provide server-operator organization administration."""
    return OperatorOrganizationsService(db_session=db_session, user_ctx=user_ctx)


OperatorOrganizationsServiceDep = Annotated[
    OperatorOrganizationsService,
    Depends(get_operator_organizations_service),
]
