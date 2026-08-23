"""Canonical route-level authorization dependencies."""

from collections.abc import Awaitable, Callable
from enum import StrEnum
from typing import Annotated

from fastapi import Depends

from app.enums import Role
from app.errors import ForbiddenOperationError
from app.security.authentication import (
    CurrentUserContextDep,
    OAuth2PrincipalContextDep,
)
from app.security.dtos import (
    AuthMethod,
    OAuth2PrincipalContext,
    UserPrincipalContext,
)
from app.security.permissions import Permission


class PermissionMode(StrEnum):
    """Permission matching mode for permission dependencies."""

    ALL = "all"
    ANY = "any"


def require_permission(
    permission: Permission,
) -> Callable[[UserPrincipalContext], Awaitable[UserPrincipalContext]]:
    """Return a dependency that requires one canonical permission."""
    return require_permissions(permission)


def require_organization_admin_permission(
    permission: Permission,
) -> Callable[[UserPrincipalContext], Awaitable[UserPrincipalContext]]:
    """Require one permission and the explicit organization-admin role."""
    permission_dependency = require_permission(permission)

    async def dependency(user_ctx: CurrentUserContextDep) -> UserPrincipalContext:
        """Require both the organization-admin role and permission."""
        if Role.ORGANIZATION_ADMIN not in user_ctx.roles:
            raise ForbiddenOperationError
        return await permission_dependency(user_ctx)

    return dependency


def require_operator_permission(
    permission: Permission,
) -> Callable[[UserPrincipalContext], Awaitable[UserPrincipalContext]]:
    """Require one permission and the explicit server-operator role."""
    permission_dependency = require_permission(permission)

    async def dependency(
        user_ctx: Annotated[UserPrincipalContext, Depends(permission_dependency)],
    ) -> UserPrincipalContext:
        """Require the explicit server-operator role."""
        if not user_ctx.is_operator:
            raise ForbiddenOperationError
        return user_ctx

    return dependency


def require_permissions(
    *required_permissions: Permission,
    mode: PermissionMode = PermissionMode.ALL,
) -> Callable[[UserPrincipalContext], Awaitable[UserPrincipalContext]]:
    """Return a dependency that requires canonical route permissions."""
    required = frozenset(Permission(permission) for permission in required_permissions)

    async def dependency(user_ctx: CurrentUserContextDep) -> UserPrincipalContext:
        """Validate required permissions for the current principal."""
        if not required:
            return user_ctx
        permissions = user_ctx.permissions
        if user_ctx.auth_method == AuthMethod.OAUTH2:
            permissions = frozenset(
                permission
                for permission in permissions
                if permission.value in user_ctx.scopes
            )
        allowed = (
            bool(required & permissions)
            if mode == PermissionMode.ANY
            else required <= permissions
        )
        if not allowed:
            raise ForbiddenOperationError
        return user_ctx

    return dependency


def require_oauth2_scopes(
    *required_scopes: str,
) -> Callable[[OAuth2PrincipalContext], Awaitable[OAuth2PrincipalContext]]:
    """Return a dependency that requires OAuth2 bearer scopes."""

    async def dependency(
        principal_ctx: OAuth2PrincipalContextDep,
    ) -> OAuth2PrincipalContext:
        """Validate required OAuth2 scopes for the current principal."""
        missing_scopes = set(required_scopes) - principal_ctx.scopes
        if missing_scopes:
            raise ForbiddenOperationError
        return principal_ctx

    return dependency


async def get_current_operator_context(
    user_ctx: CurrentUserContextDep,
) -> UserPrincipalContext:
    """Restrict access to control-plane operators only."""
    if not user_ctx.is_operator:
        raise ForbiddenOperationError
    return user_ctx


CurrentOperatorContextDep = Annotated[
    UserPrincipalContext, Depends(get_current_operator_context)
]
