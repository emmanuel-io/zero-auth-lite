"""Authentication and authorization dependencies for management pages."""

from typing import Annotated

from fastapi import Depends

from app.browser_sessions.dependencies import (
    CurrentBrowserFormUserContextDep,
    CurrentBrowserUserContextDep,
)
from app.core.errors.common import ForbiddenOperationError
from app.db.dependencies import DbSessionDep
from app.identity.dependencies import UserLifecycleServiceDep
from app.identity.services.organization_metadata import OrganizationMetadataService
from app.identity.services.organization_users import OrganizationUsersService
from app.identity.services.server_organizations import ServerOrganizationsService
from app.identity.services.server_users import ServerUsersService
from app.security.principals import BrowserUserPrincipalContext
from app.security.roles import Role


async def require_organization_admin_ui(
    user_ctx: CurrentBrowserUserContextDep,
) -> BrowserUserPrincipalContext:
    """Require a browser session carrying current organization-admin authority."""
    if Role.ORGANIZATION_ADMIN not in user_ctx.roles:
        raise ForbiddenOperationError
    return user_ctx


async def require_organization_admin_form(
    user_ctx: CurrentBrowserFormUserContextDep,
) -> BrowserUserPrincipalContext:
    """Require organization-admin authority and authenticated form CSRF."""
    if Role.ORGANIZATION_ADMIN not in user_ctx.roles:
        raise ForbiddenOperationError
    return user_ctx


async def require_operator_ui(
    user_ctx: CurrentBrowserUserContextDep,
) -> BrowserUserPrincipalContext:
    """Require a browser session carrying current server-operator authority."""
    if not user_ctx.is_operator:
        raise ForbiddenOperationError
    return user_ctx


async def require_operator_form(
    user_ctx: CurrentBrowserFormUserContextDep,
) -> BrowserUserPrincipalContext:
    """Require server-operator authority and authenticated form CSRF."""
    if not user_ctx.is_operator:
        raise ForbiddenOperationError
    return user_ctx


OrganizationAdminUIDep = Annotated[
    BrowserUserPrincipalContext, Depends(require_organization_admin_ui)
]
OrganizationAdminFormDep = Annotated[
    BrowserUserPrincipalContext, Depends(require_organization_admin_form)
]
OperatorUIDep = Annotated[BrowserUserPrincipalContext, Depends(require_operator_ui)]
OperatorFormDep = Annotated[BrowserUserPrincipalContext, Depends(require_operator_form)]


def get_organization_ui_users_service(
    db_session: DbSessionDep,
    user_ctx: OrganizationAdminUIDep,
    lifecycle: UserLifecycleServiceDep,
) -> OrganizationUsersService:
    """Bind organization user reads to the browser administrator."""
    return OrganizationUsersService(
        db_session=db_session, actor_ctx=user_ctx, lifecycle=lifecycle
    )


def get_organization_form_users_service(
    db_session: DbSessionDep,
    user_ctx: OrganizationAdminFormDep,
    lifecycle: UserLifecycleServiceDep,
) -> OrganizationUsersService:
    """Bind organization user mutations to the CSRF-validated administrator."""
    return OrganizationUsersService(
        db_session=db_session, actor_ctx=user_ctx, lifecycle=lifecycle
    )


def get_organization_ui_metadata_service(
    db_session: DbSessionDep, user_ctx: OrganizationAdminUIDep
) -> OrganizationMetadataService:
    """Bind organization metadata reads to the browser administrator."""
    return OrganizationMetadataService(db_session=db_session, actor_ctx=user_ctx)


def get_organization_form_metadata_service(
    db_session: DbSessionDep, user_ctx: OrganizationAdminFormDep
) -> OrganizationMetadataService:
    """Bind organization metadata writes to the CSRF-validated administrator."""
    return OrganizationMetadataService(db_session=db_session, actor_ctx=user_ctx)


def get_operator_ui_users_service(
    db_session: DbSessionDep,
    user_ctx: OperatorUIDep,
    lifecycle: UserLifecycleServiceDep,
) -> ServerUsersService:
    """Bind global user reads to the browser operator."""
    return ServerUsersService(
        db_session=db_session, actor_ctx=user_ctx, lifecycle=lifecycle
    )


def get_operator_form_users_service(
    db_session: DbSessionDep,
    user_ctx: OperatorFormDep,
    lifecycle: UserLifecycleServiceDep,
) -> ServerUsersService:
    """Bind global user writes to the CSRF-validated browser operator."""
    return ServerUsersService(
        db_session=db_session, actor_ctx=user_ctx, lifecycle=lifecycle
    )


def get_operator_ui_organizations_service(
    db_session: DbSessionDep, user_ctx: OperatorUIDep
) -> ServerOrganizationsService:
    """Bind organization reads to the browser operator."""
    return ServerOrganizationsService(db_session=db_session, actor_ctx=user_ctx)


def get_operator_form_organizations_service(
    db_session: DbSessionDep, user_ctx: OperatorFormDep
) -> ServerOrganizationsService:
    """Bind organization writes to the CSRF-validated browser operator."""
    return ServerOrganizationsService(db_session=db_session, actor_ctx=user_ctx)


OrganizationUIUsersServiceDep = Annotated[
    OrganizationUsersService, Depends(get_organization_ui_users_service)
]
OrganizationFormUsersServiceDep = Annotated[
    OrganizationUsersService, Depends(get_organization_form_users_service)
]
OrganizationUIMetadataServiceDep = Annotated[
    OrganizationMetadataService, Depends(get_organization_ui_metadata_service)
]
OrganizationFormMetadataServiceDep = Annotated[
    OrganizationMetadataService, Depends(get_organization_form_metadata_service)
]
OperatorUIUsersServiceDep = Annotated[
    ServerUsersService, Depends(get_operator_ui_users_service)
]
OperatorFormUsersServiceDep = Annotated[
    ServerUsersService, Depends(get_operator_form_users_service)
]
OperatorUIOrganizationsServiceDep = Annotated[
    ServerOrganizationsService, Depends(get_operator_ui_organizations_service)
]
OperatorFormOrganizationsServiceDep = Annotated[
    ServerOrganizationsService, Depends(get_operator_form_organizations_service)
]
