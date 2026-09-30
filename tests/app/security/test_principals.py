"""Tests for concrete authentication principal contexts."""

from datetime import datetime, UTC

import pytest
from app.security.permissions import Permission, permissions_for_roles
from app.security.principals import (
    AuthenticationMechanism,
    BrowserUserPrincipalContext,
    OAuth2ClientPrincipalContext,
    OAuth2UserPrincipalContext,
)
from app.security.roles import Role

from tests.identifiers import deterministic_uuid, PublicId


pytestmark = pytest.mark.unit


def test_concrete_principals_expose_their_authentication_authority() -> None:
    """Distinguish browser users, OAuth2 users, and OAuth2 clients by type."""

    user_oauth2_session_id = 3
    client_oauth2_session_id = 4
    browser = BrowserUserPrincipalContext(
        user_id=1,
        organization_id=2,
        raw_session_id="raw-browser-session",
        user_public_id=PublicId(1),
        organization_public_id=PublicId(2),
    )
    oauth2_user = OAuth2UserPrincipalContext(
        user_id=1,
        organization_id=2,
        oauth2_session_id=user_oauth2_session_id,
        client_id=deterministic_uuid("user-client"),
        user_public_id=PublicId(1),
        organization_public_id=PublicId(2),
    )
    oauth2_client = OAuth2ClientPrincipalContext(
        organization_id=2,
        oauth2_session_id=client_oauth2_session_id,
        client_id=deterministic_uuid("machine-client"),
    )

    assert browser.authentication_mechanism is AuthenticationMechanism.BROWSER_SESSION
    assert browser.raw_session_id == "raw-browser-session"
    assert not hasattr(browser, "oauth2_session_id")
    assert browser.client_id is None
    assert oauth2_user.authentication_mechanism is AuthenticationMechanism.OAUTH2_BEARER
    assert oauth2_user.oauth2_session_id == user_oauth2_session_id
    assert not hasattr(oauth2_user, "raw_session_id")
    assert oauth2_user.client_id == deterministic_uuid("user-client")
    assert (
        oauth2_client.authentication_mechanism is AuthenticationMechanism.OAUTH2_BEARER
    )
    assert oauth2_client.oauth2_session_id == client_oauth2_session_id
    assert not hasattr(oauth2_client, "raw_session_id")
    assert oauth2_client.client_id == deterministic_uuid("machine-client")
    assert oauth2_client.scopes == frozenset()


@pytest.mark.parametrize(
    ("principal_type", "kwargs"),
    [
        (
            BrowserUserPrincipalContext,
            {
                "user_id": 1,
                "organization_id": 2,
                "raw_session_id": "session",
                "machine_organization_access": "single",
            },
        ),
        (
            OAuth2UserPrincipalContext,
            {
                "user_id": 1,
                "organization_id": 2,
                "oauth2_session_id": 3,
                "client_id": deterministic_uuid("client"),
                "machine_organization_access": "single",
            },
        ),
        (
            OAuth2ClientPrincipalContext,
            {
                "organization_id": 2,
                "oauth2_session_id": 3,
                "client_id": deterministic_uuid("client"),
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
        principal_type(**kwargs)


def test_role_and_authentication_mechanism_enums_match_current_values() -> None:
    """Keep future authentication concepts out of the canonical contracts."""
    assert {role.value for role in Role} == {"operator", "organization_admin"}
    assert {mechanism.value for mechanism in AuthenticationMechanism} == {
        "browser_session",
        "oauth2_bearer",
    }


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
        "sessions:write",
        "oauth2_clients:read",
        "oauth2_clients:write",
    }


def test_user_principal_normalizes_roles_and_permissions() -> None:
    """Derive canonical permissions for every concrete user transport."""
    principal = BrowserUserPrincipalContext(
        user_id=1,
        organization_id=2,
        raw_session_id="session",
        user_public_id=PublicId(1),
        organization_public_id=PublicId(2),
        roles=frozenset({Role.ORGANIZATION_ADMIN, Role.OPERATOR}),
    )

    assert principal.has_administrative_role is True
    assert principal.is_operator is True
    assert Permission.ORGANIZATION_READ in principal.permissions
    assert Permission.USERS_READ in principal.permissions


def test_browser_principal_exposes_display_only_identity_context() -> None:
    """Build navigation labels without turning them into authorization state."""
    principal = BrowserUserPrincipalContext(
        user_id=1,
        organization_id=2,
        raw_session_id="session",
        user_public_id=PublicId(1),
        organization_public_id=PublicId(2),
        first_name="Ada",
        last_name="Lovelace",
        organization_name="Analytical Engines",
    )

    assert principal.display_name == "Ada Lovelace"
    assert principal.organization_name == "Analytical Engines"
    assert principal.roles == frozenset()


def test_browser_principal_uses_email_when_display_name_is_blank() -> None:
    """Keep the signed-in identity understandable when profile names are empty."""
    principal = BrowserUserPrincipalContext(
        user_id=1,
        organization_id=2,
        raw_session_id="session",
        user_public_id=PublicId(1),
        organization_public_id=PublicId(2),
        email="ada@example.com",
    )

    assert principal.display_name == "ada@example.com"


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
    assert Permission.SESSIONS_WRITE in operator_permissions
    assert Permission.ORGANIZATION_READ not in operator_permissions


def test_only_browser_principals_carry_interactive_authentication_time() -> None:
    """Keep interactive authentication time on browser principals only."""
    authenticated_at = datetime(2026, 8, 6, 1, 2, 3, tzinfo=UTC)
    known = BrowserUserPrincipalContext(
        user_id=1,
        organization_id=2,
        raw_session_id="session",
        user_public_id=PublicId(1),
        organization_public_id=PublicId(2),
        authenticated_at=authenticated_at,
    )

    assert known.authenticated_at is authenticated_at
    with pytest.raises(TypeError, match="unexpected keyword argument"):
        OAuth2UserPrincipalContext(
            user_id=1,
            organization_id=2,
            oauth2_session_id=3,
            client_id=deterministic_uuid("client"),
            user_public_id=PublicId(1),
            organization_public_id=PublicId(2),
            authenticated_at=authenticated_at,  # type: ignore[call-arg]  # ty: ignore[unknown-argument]
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
        "permissions": frozenset({Permission.USERS_WRITE}),
    }
    if principal_type is OAuth2UserPrincipalContext:
        kwargs["client_id"] = "client"
        kwargs["oauth2_session_id"] = 3
    else:
        kwargs["raw_session_id"] = "session"
    with pytest.raises(TypeError, match="unexpected keyword argument"):
        principal_type(**kwargs)
