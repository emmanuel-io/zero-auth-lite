"""Tests for route-level authorization dependencies."""

import pytest
from app.enums import Role
from app.errors import ForbiddenOperationError
from app.security.authorization import (
    get_current_operator_context,
    PermissionMode,
    require_oauth2_scopes,
    require_organization_admin_permission,
    require_permission,
    require_permissions,
)
from app.security.dtos import (
    BrowserUserPrincipalContext,
    OAuth2UserPrincipalContext,
)
from app.security.permissions import Permission


pytestmark = pytest.mark.unit


@pytest.mark.asyncio
@pytest.mark.negative
async def test_operator_and_scope_dependencies_accept_and_reject_contexts() -> None:
    """Assert operator and OAuth2 scope dependencies enforce privileges."""
    admin_user = BrowserUserPrincipalContext(
        user_id=1,
        organization_id=2,
        session_id="session",
        roles=frozenset({Role.ORGANIZATION_ADMIN}),
    )
    scoped_principal = OAuth2UserPrincipalContext(
        organization_id=2,
        session_id=3,
        user_id=1,
        client_id="client",
        scopes=frozenset({"read"}),
    )
    operator_user = BrowserUserPrincipalContext(
        user_id=1,
        organization_id=2,
        session_id="session",
        roles=frozenset({Role.OPERATOR}),
    )
    assert await get_current_operator_context(operator_user) == operator_user
    assert await require_oauth2_scopes("read")(scoped_principal) == scoped_principal

    with pytest.raises(ForbiddenOperationError):
        await get_current_operator_context(admin_user)

    with pytest.raises(ForbiddenOperationError):
        await require_oauth2_scopes("write")(scoped_principal)


@pytest.mark.asyncio
@pytest.mark.negative
async def test_permission_dependencies_accept_and_reject_contexts() -> None:
    """Assert canonical permission dependencies enforce permissions."""
    ordinary_user = BrowserUserPrincipalContext(
        user_id=1,
        organization_id=2,
        session_id="session",
    )
    operator = BrowserUserPrincipalContext(
        user_id=1,
        organization_id=2,
        session_id="session",
        roles=frozenset({Role.OPERATOR}),
    )

    assert await require_permission(Permission.USERS_READ)(operator) == operator
    assert (
        await require_permissions(
            Permission.USERS_READ,
            Permission.USERS_WRITE,
            mode=PermissionMode.ANY,
        )(operator)
        == operator
    )

    with pytest.raises(ForbiddenOperationError) as exc_info:
        await require_permission(Permission.USERS_WRITE)(ordinary_user)

    assert exc_info.value.code == "FORBIDDEN_OPERATION"


@pytest.mark.asyncio
@pytest.mark.negative
async def test_oauth2_user_permissions_are_limited_by_granted_scopes() -> None:
    """Assert a bearer cannot use role permissions absent from its token scopes."""
    scoped_admin = OAuth2UserPrincipalContext(
        user_id=1,
        organization_id=2,
        session_id=3,
        client_id="client",
        roles=frozenset({Role.ORGANIZATION_ADMIN}),
        scopes=frozenset({Permission.ORGANIZATION_READ.value}),
    )

    assert (
        await require_permission(Permission.ORGANIZATION_READ)(scoped_admin)
        == scoped_admin
    )
    with pytest.raises(ForbiddenOperationError) as exc_info:
        await require_permission(Permission.ORGANIZATION_WRITE)(scoped_admin)

    assert exc_info.value.code == "FORBIDDEN_OPERATION"


@pytest.mark.asyncio
@pytest.mark.negative
async def test_organization_scope_does_not_grant_organization_admin_role() -> None:
    """Keep the organization-admin role mandatory when organization scope is present."""
    scoped_member = OAuth2UserPrincipalContext(
        user_id=1,
        organization_id=2,
        session_id=3,
        client_id="client",
        scopes=frozenset({Permission.ORGANIZATION_READ.value}),
    )

    with pytest.raises(ForbiddenOperationError) as exc_info:
        await require_organization_admin_permission(Permission.ORGANIZATION_READ)(
            scoped_member
        )

    assert exc_info.value.code == "FORBIDDEN_OPERATION"
