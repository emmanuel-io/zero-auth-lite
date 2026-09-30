"""Black-box tests for the current-user account browser page."""

import re

import httpx
import pytest
from app.db.models.organization_membership import OrganizationMembershipDB
from app.db.models.user import UserDB
from app.identity.users.enums import OrganizationMembershipRole
from fastapi import FastAPI, status
from sqlalchemy import update

from tests.fixtures.auth import login_browser, UserCredentials
from tests.fixtures.settings import app_settings
from tests.routes.management.helpers import with_external_management_presentation


pytestmark = pytest.mark.api
TEST_ORIGIN = "http://testserver"


def _csrf(response: httpx.Response) -> str:
    match = re.search(r'name="csrf_token" value="([^"]+)"', response.text)
    assert match is not None
    return match.group(1)


@pytest.mark.asyncio
@with_external_management_presentation()
async def test_account_page_requires_a_browser_session(
    client: httpx.AsyncClient,
) -> None:
    """Redirect anonymous users to the configured authentication entry point."""
    response = await client.get("/management/account", follow_redirects=False)

    assert response.status_code == status.HTTP_303_SEE_OTHER
    assert response.headers["location"].startswith("https://frontend.test/login?")
    assert "return_url=%2Fmanagement%2Faccount" in response.headers["location"]


@pytest.mark.asyncio
async def test_user_can_update_profile_from_account_page(
    client: httpx.AsyncClient,
    verified_user_credentials: UserCredentials,
) -> None:
    """Update self-owned fields and retain email verification policy."""
    await login_browser(client, verified_user_credentials)
    account = await client.get("/management/account")

    missing_csrf = await client.post(
        "/management/account",
        data={
            "email": "pending-account@example.com",
            "first_name": "Updated",
            "last_name": "Profile",
        },
        headers={"Origin": TEST_ORIGIN},
        follow_redirects=False,
    )
    updated = await client.post(
        "/management/account",
        data={
            "email": "pending-account@example.com",
            "first_name": "Updated",
            "last_name": "Profile",
            "csrf_token": _csrf(account),
        },
        headers={"Origin": TEST_ORIGIN},
        follow_redirects=False,
    )
    refreshed = await client.get(updated.headers["location"])

    assert account.status_code == status.HTTP_200_OK
    assert 'src="/static/vendor/htmx-4.0.0-beta6.min.js"' in account.text
    assert "Update your personal profile." in account.text
    assert "verify the new address" in account.text
    assert "<h1>Account</h1>" not in account.text
    assert "Test Organization" in account.text
    assert "Admin User" in account.text
    assert 'class="app-identity"' in account.text
    assert "Role: admin" not in account.text
    assert missing_csrf.status_code == status.HTTP_403_FORBIDDEN
    assert updated.status_code == status.HTTP_303_SEE_OTHER
    assert updated.headers["location"] == ("/management/account?notice=profile-updated")
    assert 'value="Updated"' in refreshed.text
    assert 'value="Profile"' in refreshed.text
    assert 'value="admin@example.com"' in refreshed.text
    assert "Pending verification: pending-account@example.com" in refreshed.text


@pytest.mark.asyncio
@with_external_management_presentation()
async def test_account_page_is_available_without_an_administrative_role(
    app: FastAPI,
    client: httpx.AsyncClient,
    verified_user_credentials: UserCredentials,
) -> None:
    """Keep profile self-service independent from management authority."""
    async with app.state.core_session_factory.begin() as session:
        await session.execute(
            update(OrganizationMembershipDB).values(
                role=OrganizationMembershipRole.MEMBER
            )
        )
        await session.execute(update(UserDB).values(is_operator=False))

    await login_browser(client, verified_user_credentials)
    account = await client.get("/management/account")

    assert account.status_code == status.HTTP_200_OK
    assert "Test Organization" in account.text
    assert "Admin User" in account.text
    assert 'class="app-identity"' in account.text
    assert "Role: member" not in account.text
    assert 'href="/management/organization"' not in account.text
    assert 'href="/management/operator"' not in account.text
    assert 'href="/management/account"' in account.text
    assert 'href="/management/account" aria-current="page"' in account.text
    assert '<details class="app-menu app-menu--mobile">' in account.text
    assert 'href="https://frontend.test/logout"' in account.text


@pytest.mark.asyncio
@with_external_management_presentation()
async def test_management_dashboard_requires_browser_session_and_redirects_htmx(
    client: httpx.AsyncClient,
) -> None:
    """Reject bearer-only access and use full navigation for htmx requests."""
    ordinary = await client.get(
        "/management",
        headers={"Authorization": "Bearer opaque-token"},
        follow_redirects=False,
    )
    htmx = await client.get(
        "/management",
        headers={"HX-Request": "true", "Cookie": "sessionid=expired"},
        follow_redirects=False,
    )

    assert ordinary.status_code == status.HTTP_303_SEE_OTHER
    assert ordinary.headers["location"].startswith("https://frontend.test/login?")
    assert htmx.status_code == status.HTTP_204_NO_CONTENT
    assert htmx.headers["HX-Redirect"].startswith("https://frontend.test/login?")


@pytest.mark.asyncio
@with_external_management_presentation()
async def test_external_authentication_does_not_mount_ungrouped_management_paths(
    client: httpx.AsyncClient,
) -> None:
    """Expose only the grouped management surface in external mode."""
    for path in ("/", "/account", "/organization", "/admin"):
        response = await client.get(path, follow_redirects=False)
        assert response.status_code == status.HTTP_404_NOT_FOUND


@pytest.mark.asyncio
@app_settings(ui={"management_authentication": "builtin"})
@pytest.mark.parametrize(
    "authority",
    [
        (OrganizationMembershipRole.MEMBER, False, False, False),
        (OrganizationMembershipRole.ADMIN, False, True, False),
        (OrganizationMembershipRole.MEMBER, True, False, True),
        (OrganizationMembershipRole.ADMIN, True, True, True),
    ],
)
async def test_authenticated_dashboard_navigation_matches_current_authority(
    app: FastAPI,
    client: httpx.AsyncClient,
    verified_user_credentials: UserCredentials,
    authority: tuple[OrganizationMembershipRole, bool, bool, bool],
) -> None:
    """Expose only the authenticated destinations granted to the current user."""
    role, is_operator, show_organization, show_operator = authority
    async with app.state.core_session_factory.begin() as session:
        await session.execute(update(OrganizationMembershipDB).values(role=role))
        await session.execute(update(UserDB).values(is_operator=is_operator))

    login = await client.get("/login")
    response = await client.post(
        "/login",
        data={
            "email": verified_user_credentials.email,
            "password": verified_user_credentials.password,
            "csrf_token": _csrf(login),
        },
        headers={"Origin": TEST_ORIGIN},
        follow_redirects=False,
    )
    root = await client.get("/", follow_redirects=False)
    dashboard = await client.get("/management")

    assert response.status_code == status.HTTP_303_SEE_OTHER
    assert root.status_code == status.HTTP_303_SEE_OTHER
    assert root.headers["location"] == "/management"
    assert dashboard.status_code == status.HTTP_200_OK
    assert 'href="/management" aria-current="page"' in dashboard.text
    assert 'href="/management/account"' in dashboard.text
    assert 'href="/logout"' in dashboard.text
    assert ('href="/management/organization"' in dashboard.text) is show_organization
    assert ('href="/management/operator"' in dashboard.text) is show_operator
