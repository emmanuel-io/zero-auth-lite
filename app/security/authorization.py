"""Canonical route-level authorization dependencies."""

from collections.abc import Awaitable, Callable
from enum import StrEnum
from typing import Annotated

from fastapi import Depends

from app.core.errors.common import ForbiddenOperationError
from app.security.authentication import CurrentUserContextDep
from app.security.permissions import Permission
from app.security.principals import UserPrincipalContext
from app.security.roles import Role


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
        allowed = (
            bool(required & user_ctx.permissions)
            if mode == PermissionMode.ANY
            else required <= user_ctx.permissions
        )
        if not allowed:
            raise ForbiddenOperationError
        return user_ctx

    return dependency
