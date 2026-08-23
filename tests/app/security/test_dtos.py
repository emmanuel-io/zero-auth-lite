"""Tests for concrete authentication principal contexts."""

from datetime import datetime, UTC

import pytest
from app.enums import Role
from app.oauth2.clients.access import OAuth2ClientMachineOrganizationAccess
from app.security.dtos import (
    AuthMethod,
    BrowserUserPrincipalContext,
    OAuth2ClientPrincipalContext,
    OAuth2UserPrincipalContext,
)
from app.security.permissions import Permission, permissions_for_roles


pytestmark = pytest.mark.unit


def test_concrete_principals_expose_their_authentication_authority() -> None:
    """Distinguish browser users, OAuth2 users, and OAuth2 clients by type."""
    browser = BrowserUserPrincipalContext(
        user_id=1,
        organization_id=2,
        session_id="raw-browser-session",
    )
    oauth2_user = OAuth2UserPrincipalContext(
        user_id=1,
        organization_id=2,
        session_id=3,
        client_id="user-client",
    )
    oauth2_client = OAuth2ClientPrincipalContext(
        organization_id=2,
        session_id=4,
        client_id="machine-client",
        machine_organization_access=OAuth2ClientMachineOrganizationAccess.SINGLE,
    )

    assert browser.auth_method == AuthMethod.SESSION
    assert browser.client_id is None
    assert oauth2_user.auth_method == AuthMethod.OAUTH2
    assert oauth2_user.client_id == "user-client"
    assert oauth2_client.auth_method == AuthMethod.OAUTH2
    assert oauth2_client.client_id == "machine-client"
    assert oauth2_client.scopes == frozenset()


@pytest.mark.parametrize(
    ("principal_type", "kwargs"),
    [
        (
            BrowserUserPrincipalContext,
            {
                "user_id": 1,
                "organization_id": 2,
                "session_id": "session",
                "machine_organization_access": "single",
            },
        ),
        (
            OAuth2UserPrincipalContext,
            {
                "user_id": 1,
                "organization_id": 2,
                "session_id": 3,
                "client_id": "client",
                "machine_organization_access": "single",
            },
        ),
        (
            OAuth2ClientPrincipalContext,
            {
                "organization_id": 2,
                "session_id": 3,
                "client_id": "client",
                "machine_organization_access": "single",
                "user_id": 1,
            },
        ),
    ],
)
def test_concrete_principals_reject_fields_owned_by_another_actor(
    principal_type: type[object], kwargs: dict[str, object]
) -> None:
    """Make mixed user and client authority unrepresentable."""
    with pytest.raises(TypeError, match="unexpected keyword argument"):
        principal_type(**kwargs)  # type: ignore[call-arg]


def test_role_and_auth_method_enums_only_expose_implemented_values() -> None:
    """Keep future authentication concepts out of the canonical contracts."""
    assert {role.value for role in Role} == {"operator", "organization_admin"}
    assert {method.value for method in AuthMethod} == {"session", "oauth2"}


def test_permission_set_only_contains_auth_concepts() -> None:
    """Assert product-domain permissions stay outside the auth example model."""
    assert {permission.value for permission in Permission} == {
        "profile:read",
        "profile:write",
        "organization:read",
        "organization:write",
        "organizations:read",
        "organizations:write",
        "users:read",
        "users:write",
        "oauth2_clients:read",
        "oauth2_clients:write",
    }


def test_user_principal_normalizes_roles_and_permissions() -> None:
    """Derive canonical permissions for every concrete user transport."""
    principal = BrowserUserPrincipalContext(
        user_id=1,
        organization_id=2,
        session_id="session",
        roles=frozenset({Role.ORGANIZATION_ADMIN, Role.OPERATOR}),
    )

    assert principal.has_administrative_role is True
    assert principal.is_operator is True
    assert Permission.ORGANIZATION_READ in principal.permissions
    assert Permission.USERS_READ in principal.permissions


def test_permissions_for_roles_maps_current_role_boundaries() -> None:
    """Assert role-derived permission sets preserve current access boundaries."""
    organization_user_permissions = permissions_for_roles(frozenset())
    organization_admin_permissions = permissions_for_roles(
        frozenset({Role.ORGANIZATION_ADMIN})
    )
    operator_permissions = permissions_for_roles(frozenset({Role.OPERATOR}))

    assert Permission.PROFILE_READ in organization_user_permissions
    assert Permission.USERS_READ not in organization_user_permissions
    assert Permission.ORGANIZATION_READ in organization_admin_permissions
    assert Permission.USERS_WRITE not in organization_admin_permissions
    assert Permission.USERS_WRITE in operator_permissions
    assert Permission.ORGANIZATION_READ not in operator_permissions


def test_only_browser_principals_carry_interactive_authentication_time() -> None:
    """Keep interactive authentication time on browser principals only."""
    authenticated_at = datetime(2026, 8, 6, 1, 2, 3, tzinfo=UTC)
    known = BrowserUserPrincipalContext(
        user_id=1,
        organization_id=2,
        session_id="session",
        authenticated_at=authenticated_at,
    )

    assert known.authenticated_at is authenticated_at
    with pytest.raises(TypeError, match="unexpected keyword argument"):
        OAuth2UserPrincipalContext(
            user_id=1,
            organization_id=2,
            session_id=3,
            client_id="client",
            authenticated_at=authenticated_at,  # type: ignore[call-arg]
        )


@pytest.mark.parametrize(
    "principal_type",
    [BrowserUserPrincipalContext, OAuth2UserPrincipalContext],
)
def test_user_principals_reject_injected_permissions(
    principal_type: type[object],
) -> None:
    """Require every user permission set to be derived from roles and scopes."""
    kwargs: dict[str, object] = {
        "user_id": 1,
        "organization_id": 2,
        "session_id": "session" if principal_type is BrowserUserPrincipalContext else 3,
        "permissions": frozenset({Permission.USERS_WRITE}),
    }
    if principal_type is OAuth2UserPrincipalContext:
        kwargs["client_id"] = "client"
    with pytest.raises(TypeError, match="unexpected keyword argument"):
        principal_type(**kwargs)  # type: ignore[call-arg]
