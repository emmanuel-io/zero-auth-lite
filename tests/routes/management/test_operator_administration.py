"""Operator organization, session, and OAuth2-client management route tests."""

import re

import httpx
import pytest
from fastapi import FastAPI, status

from tests.fixtures.auth import login_browser, UserCredentials
from tests.identifiers import UUID4_PATTERN
from tests.routes.management.helpers import with_external_management_presentation


pytestmark = pytest.mark.api
TEST_ORIGIN = "http://testserver"


def _csrf(response: httpx.Response) -> str:
    match = re.search(r'name="csrf_token" value="([^"]+)"', response.text)
    assert match is not None
    return match.group(1)


@pytest.mark.asyncio
async def test_operator_can_create_confidential_client_and_sees_secret_once(
    client: httpx.AsyncClient,
    verified_user_credentials: UserCredentials,
) -> None:
    """Render a new confidential client credential only in the write response."""
    await login_browser(client, verified_user_credentials)
    form = await client.get("/management/operator/oauth2/clients/new")

    created = await client.post(
        "/management/operator/oauth2/clients",
        data={
            "name": "Management Client",
            "grant_types": "client_credentials",
            "scopes": "users:read",
            "redirect_uris": "",
            "is_confidential": "true",
            "requires_consent": "false",
            "is_active": "true",
            "user_organization_access": "unrestricted",
            "csrf_token": _csrf(form),
        },
        headers={"Origin": TEST_ORIGIN},
    )

    assert created.status_code == status.HTTP_200_OK
    assert created.headers["Cache-Control"] == "no-store"
    assert "Save this client secret now" in created.text
    assert '<pre class="secret">' in created.text


@pytest.mark.asyncio
async def test_operator_can_create_client_through_htmx(
    client: httpx.AsyncClient,
    verified_user_credentials: UserCredentials,
) -> None:
    """Return the one-time secret as a replaceable same-origin fragment."""
    await login_browser(client, verified_user_credentials)
    form = await client.get("/management/operator/oauth2/clients/new")

    created = await client.post(
        "/management/operator/oauth2/clients",
        data={
            "name": "HTMX Client",
            "grant_types": "client_credentials",
            "scopes": "users:read",
            "redirect_uris": "",
            "is_confidential": "true",
            "is_active": "true",
            "user_organization_access": "unrestricted",
            "csrf_token": _csrf(form),
        },
        headers={"Origin": TEST_ORIGIN, "HX-Request": "true"},
    )

    assert created.status_code == status.HTTP_200_OK
    assert "Save this client secret now" in created.text
    assert '<pre class="secret">' in created.text
    assert "<!doctype html>" not in created.text


@pytest.mark.asyncio
async def test_operator_can_replace_client_and_organization_access_policies(
    client: httpx.AsyncClient,
    verified_user_credentials: UserCredentials,
) -> None:
    """Map each OAuth2 client management form to its dedicated service DTO."""
    await login_browser(client, verified_user_credentials)
    create_form = await client.get("/management/operator/oauth2/clients/new")
    created = await client.post(
        "/management/operator/oauth2/clients",
        data={
            "name": "Client before replacement",
            "grant_types": "client_credentials",
            "scopes": "users:read",
            "is_confidential": "true",
            "is_active": "true",
            "user_organization_access": "unrestricted",
            "csrf_token": _csrf(create_form),
        },
        headers={"Origin": TEST_ORIGIN},
    )
    client_match = re.search(
        rf'href="(/management/operator/oauth2/clients/{UUID4_PATTERN})"',
        created.text,
    )
    assert client_match is not None
    client_url = client_match.group(1)

    organizations = await client.get("/management/operator/organizations")
    organization_match = re.search(
        rf'href="/management/operator/organizations/({UUID4_PATTERN})"',
        organizations.text,
    )
    assert organization_match is not None
    organization_id = organization_match.group(1)
    detail = await client.get(client_url)
    csrf_token = _csrf(detail)

    replaced = await client.post(
        client_url,
        data={
            "name": "Client after replacement",
            "grant_types": "client_credentials",
            "scopes": "users:read users:write",
            "is_confidential": "true",
            "is_active": "true",
            "csrf_token": csrf_token,
        },
        headers={"Origin": TEST_ORIGIN},
        follow_redirects=False,
    )
    user_access = await client.post(
        f"{client_url}/user-organizations",
        data={
            "user_organization_access": "single",
            "organization_ids": organization_id,
            "csrf_token": csrf_token,
        },
        headers={"Origin": TEST_ORIGIN},
        follow_redirects=False,
    )
    machine_access = await client.post(
        f"{client_url}/machine-organizations",
        data={
            "machine_organization_access": "single",
            "organization_ids": organization_id,
            "csrf_token": csrf_token,
        },
        headers={"Origin": TEST_ORIGIN},
        follow_redirects=False,
    )
    refreshed = await client.get(client_url)

    assert replaced.status_code == status.HTTP_303_SEE_OTHER
    assert replaced.headers["location"] == f"{client_url}?notice=client-updated"
    assert user_access.status_code == status.HTTP_303_SEE_OTHER
    assert user_access.headers["location"] == (
        f"{client_url}?notice=user-access-updated"
    )
    assert machine_access.status_code == status.HTTP_303_SEE_OTHER
    assert machine_access.headers["location"] == (
        f"{client_url}?notice=machine-access-updated"
    )
    assert 'value="Client after replacement"' in refreshed.text
    assert 'value="users:read users:write"' in refreshed.text
    assert (
        f'<textarea id="user-organizations" name="organization_ids" rows="5">'
        f"{organization_id}</textarea>"
    ) in refreshed.text
    assert (
        f'<textarea id="machine-organizations" name="organization_ids" rows="5">'
        f"{organization_id}</textarea>"
    ) in refreshed.text


@pytest.mark.asyncio
async def test_operator_organization_links_to_its_filtered_users(
    client: httpx.AsyncClient,
    verified_user_credentials: UserCredentials,
) -> None:
    """Open operator users with the selected organization filter."""
    await login_browser(client, verified_user_credentials)
    organizations = await client.get("/management/operator/organizations")
    organization_match = re.search(
        rf'href="/management/operator/organizations/({UUID4_PATTERN})"',
        organizations.text,
    )
    assert organization_match is not None
    organization_id = organization_match.group(1)

    organization = await client.get(
        f"/management/operator/organizations/{organization_id}"
    )
    users_url = f"/management/operator/users?organization_id={organization_id}"
    invite_url = f"/management/operator/users/new?organization_id={organization_id}"
    users = await client.get(users_url)
    invite = await client.get(invite_url)

    assert f'href="{users_url}"' in organizations.text
    assert ">Manage users</a>" in organizations.text
    assert organization.status_code == status.HTTP_200_OK
    assert f'href="{users_url}"' in organization.text
    assert "Revoke security sessions" not in organization.text
    assert users.status_code == status.HTTP_200_OK
    assert f'name="organization_id" value="{organization_id}"' in users.text
    assert f'href="{invite_url}"' in users.text
    assert invite.status_code == status.HTTP_200_OK
    assert 'name="organization_id"' in invite.text
    assert f'value="{organization_id}"' in invite.text


@pytest.mark.asyncio
async def test_operator_manages_organization_sessions_from_one_page(
    client: httpx.AsyncClient,
    verified_user_credentials: UserCredentials,
) -> None:
    """Keep organization session actions on a dedicated overview page."""
    await login_browser(client, verified_user_credentials)
    organizations = await client.get("/management/operator/organizations")
    organization_match = re.search(
        rf'href="/management/operator/organizations/({UUID4_PATTERN})"',
        organizations.text,
    )
    assert organization_match is not None
    organization_id = organization_match.group(1)

    sessions_url = f"/management/operator/organizations/{organization_id}/sessions"
    browser_delete_url = (
        f"/management/operator/organizations/{organization_id}/sessions/browser/delete"
    )
    oauth2_delete_url = (
        f"/management/operator/organizations/{organization_id}/sessions/oauth2/delete"
    )
    revoke_url = f"/management/operator/organizations/{organization_id}/sessions/revoke"
    sessions = await client.get(sessions_url)
    browser_delete = await client.get(browser_delete_url)
    oauth2_delete = await client.get(oauth2_delete_url)
    revoke = await client.get(revoke_url)
    retired_browser = await client.get(
        f"/management/operator/organizations/{organization_id}/browser-sessions/delete"
    )
    retired_oauth2 = await client.get(
        f"/management/operator/organizations/{organization_id}/oauth2-sessions/delete"
    )

    assert f'href="{sessions_url}"' in organizations.text
    assert ">Manage sessions</a>" in organizations.text
    assert f'href="{revoke_url}"' not in organizations.text
    assert f'href="{browser_delete_url}"' not in organizations.text
    assert f'href="{oauth2_delete_url}"' not in organizations.text
    assert sessions.status_code == status.HTTP_200_OK
    assert f'href="{revoke_url}"' in sessions.text
    assert f'href="{browser_delete_url}"' in sessions.text
    assert f'href="{oauth2_delete_url}"' in sessions.text
    assert "<h2>Delete browser sessions</h2>" in sessions.text
    assert "<h2>Delete OAuth2 sessions</h2>" in sessions.text
    assert "<h2>Revoke all sessions</h2>" in sessions.text
    assert revoke.status_code == status.HTTP_200_OK
    assert 'class="panel form-panel danger-panel"' in revoke.text
    assert f'action="{revoke_url}"' in revoke.text
    assert browser_delete.status_code == status.HTTP_200_OK
    assert f'action="{browser_delete_url}"' in browser_delete.text
    assert "OAuth2 sessions are not affected." in browser_delete.text
    assert oauth2_delete.status_code == status.HTTP_200_OK
    assert f'action="{oauth2_delete_url}"' in oauth2_delete.text
    assert "Browser sessions are not affected." in oauth2_delete.text
    assert retired_browser.status_code == status.HTTP_404_NOT_FOUND
    assert retired_oauth2.status_code == status.HTTP_404_NOT_FOUND


@pytest.mark.asyncio
@with_external_management_presentation()
@pytest.mark.parametrize("action", ["browser/delete", "revoke"])
@pytest.mark.parametrize("transport", ["prg", "htmx"])
async def test_operator_own_organization_session_actions_end_login(
    app: FastAPI,
    client: httpx.AsyncClient,
    verified_user_credentials: UserCredentials,
    action: str,
    transport: str,
) -> None:
    """Redirect directly to login when an organization action ends authority."""
    await login_browser(client, verified_user_credentials)
    organizations = await client.get("/management/operator/organizations")
    organization_match = re.search(
        rf'href="/management/operator/organizations/({UUID4_PATTERN})"',
        organizations.text,
    )
    assert organization_match is not None
    organization_id = organization_match.group(1)
    action_url = (
        f"/management/operator/organizations/{organization_id}/sessions/{action}"
    )
    confirmation = await client.get(action_url)
    headers = {"Origin": TEST_ORIGIN}
    if transport == "htmx":
        headers["HX-Request"] = "true"

    response = await client.post(
        action_url,
        data={"confirm": "true", "csrf_token": _csrf(confirmation)},
        headers=headers,
        follow_redirects=False,
    )

    destination_header = "HX-Redirect" if transport == "htmx" else "location"
    expected_status = (
        status.HTTP_204_NO_CONTENT if transport == "htmx" else status.HTTP_303_SEE_OTHER
    )
    assert response.status_code == expected_status
    assert response.headers[destination_header].startswith(
        "https://frontend.test/login?notice="
    )
    assert any(
        cookie.startswith(f"{app.state.settings.browser_session.cookie_name}=")
        and "Max-Age=0" in cookie
        for cookie in response.headers.get_list("set-cookie")
    )
    protected = await client.get("/management/operator", follow_redirects=False)
    assert protected.status_code == status.HTTP_303_SEE_OTHER


@pytest.mark.asyncio
@pytest.mark.parametrize("action", ["browser/delete", "revoke"])
async def test_operator_other_organization_session_actions_return_to_overview(
    client: httpx.AsyncClient,
    verified_user_credentials: UserCredentials,
    action: str,
) -> None:
    """Keep the operator authenticated after acting on another organization."""
    await login_browser(client, verified_user_credentials)
    create_form = await client.get("/management/operator/organizations/new")
    created = await client.post(
        "/management/operator/organizations",
        data={"name": "Session Target", "csrf_token": _csrf(create_form)},
        headers={"Origin": TEST_ORIGIN},
        follow_redirects=False,
    )
    organization_url = created.headers["location"].split("?", 1)[0]
    overview_url = f"{organization_url}/sessions"
    action_url = f"{overview_url}/{action}"
    confirmation = await client.get(action_url)

    response = await client.post(
        action_url,
        data={"confirm": "true", "csrf_token": _csrf(confirmation)},
        headers={"Origin": TEST_ORIGIN},
        follow_redirects=False,
    )

    assert response.status_code == status.HTTP_303_SEE_OTHER
    assert response.headers["location"].startswith(f"{overview_url}?notice=")
    assert (await client.get("/management/operator")).status_code == status.HTTP_200_OK
