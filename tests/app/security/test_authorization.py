"""Tests for route-level authorization dependencies."""

import pytest
from app.core.errors.common import ForbiddenOperationError
from app.security.authorization import (
    PermissionMode,
    require_organization_admin_permission,
    require_permission,
    require_permissions,
)
from app.security.permissions import Permission
from app.security.principals import (
    BrowserUserPrincipalContext,
    OAuth2UserPrincipalContext,
)
from app.security.roles import Role

from tests.identifiers import deterministic_uuid, PublicId


pytestmark = pytest.mark.unit


@pytest.mark.asyncio
@pytest.mark.negative
async def test_permission_dependencies_accept_and_reject_contexts() -> None:
    """Assert canonical permission dependencies enforce permissions."""
    ordinary_user = BrowserUserPrincipalContext(
        user_id=1,
        organization_id=2,
        raw_session_id="session",
        user_public_id=PublicId(1),
        organization_public_id=PublicId(2),
    )
    operator = BrowserUserPrincipalContext(
        user_id=1,
        organization_id=2,
        raw_session_id="session",
        user_public_id=PublicId(1),
        organization_public_id=PublicId(2),
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
        oauth2_session_id=3,
        client_id=deterministic_uuid("client"),
        user_public_id=PublicId(1),
        organization_public_id=PublicId(2),
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
        oauth2_session_id=3,
        client_id=deterministic_uuid("client"),
        user_public_id=PublicId(1),
        organization_public_id=PublicId(2),
        scopes=frozenset({Permission.ORGANIZATION_READ.value}),
    )

    with pytest.raises(ForbiddenOperationError) as exc_info:
        await require_organization_admin_permission(Permission.ORGANIZATION_READ)(
            scoped_member
        )

    assert exc_info.value.code == "FORBIDDEN_OPERATION"
