"""Management access-control and session-administration route tests."""

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


async def _create_session_target(client: httpx.AsyncClient) -> str:
    """Create one organization-managed user and return its public ID."""
    create_form = await client.get("/management/organization/users/new")
    await client.post(
        "/management/organization/users",
        data={
            "email": "session-target@example.com",
            "first_name": "Session",
            "last_name": "Target",
            "role": "member",
            "is_active": "true",
            "csrf_token": _csrf(create_form),
        },
        headers={"Origin": TEST_ORIGIN},
    )
    users = await client.get(
        "/management/organization/users", params={"q": "session-target"}
    )
    user_match = re.search(
        rf'href="/management/organization/users/({UUID4_PATTERN})"', users.text
    )
    assert user_match is not None
    return user_match.group(1)


@pytest.mark.asyncio
@with_external_management_presentation()
async def test_management_pages_require_a_browser_session(
    client: httpx.AsyncClient,
) -> None:
    """Redirect anonymous users to the configured authentication entry point."""
    response = await client.get("/management/organization", follow_redirects=False)

    assert response.status_code == status.HTTP_303_SEE_OTHER
    assert response.headers["location"].startswith("https://frontend.test/login?")
    assert "return_url=%2Fmanagement%2Forganization" in response.headers["location"]


@pytest.mark.asyncio
@pytest.mark.negative
async def test_management_confirmation_rejects_false_value(
    client: httpx.AsyncClient,
    verified_user_credentials: UserCredentials,
) -> None:
    """Reject direct submissions that do not affirm a destructive action."""
    await login_browser(client, verified_user_credentials)
    confirmation = await client.get("/management/operator/sessions/revoke")

    response = await client.post(
        "/management/operator/sessions/revoke",
        data={"confirm": "false", "csrf_token": _csrf(confirmation)},
        headers={"Origin": TEST_ORIGIN},
        follow_redirects=False,
    )

    assert response.status_code == status.HTTP_422_UNPROCESSABLE_CONTENT
    assert (await client.get("/management/operator")).status_code == status.HTTP_200_OK


@pytest.mark.asyncio
@with_external_management_presentation()
async def test_combined_role_user_can_open_both_management_interfaces(
    client: httpx.AsyncClient,
    verified_user_credentials: UserCredentials,
) -> None:
    """Render role-specific navigation and the pinned local htmx asset."""
    login = await login_browser(client, verified_user_credentials)
    assert login.status_code == status.HTTP_204_NO_CONTENT

    organization = await client.get("/management/organization")
    operator = await client.get("/management/operator")
    asset = await client.get("/static/vendor/htmx-4.0.0-beta6.min.js")

    assert organization.status_code == status.HTTP_200_OK
    assert operator.status_code == status.HTTP_200_OK
    assert 'href="/management/organization"' in operator.text
    assert 'href="/management/operator"' in organization.text
    assert 'href="/management/organization" aria-current="page"' in organization.text
    assert 'href="/management/operator" aria-current="page"' in operator.text
    assert '<details class="app-menu app-menu--mobile">' in operator.text
    assert 'class="app-nav app-nav--desktop"' in operator.text
    assert 'href="/management/account"' in operator.text
    assert 'href="https://frontend.test/logout"' in operator.text
    assert 'src="/static/vendor/htmx-4.0.0-beta6.min.js"' in operator.text
    assert "script-src 'self'" in operator.headers["Content-Security-Policy"]
    assert "connect-src 'self'" in operator.headers["Content-Security-Policy"]
    assert asset.status_code == status.HTTP_200_OK
    assert "htmx" in asset.text


@pytest.mark.asyncio
async def test_organization_form_uses_session_csrf_and_prg(
    app: FastAPI,
    client: httpx.AsyncClient,
    verified_user_credentials: UserCredentials,
) -> None:
    """Accept hidden session CSRF for ordinary HTML forms and htmx forms."""
    await login_browser(client, verified_user_credentials)
    dashboard = await client.get("/management/organization")
    page = await client.get("/management/organization/settings")
    csrf_token = _csrf(page)

    missing = await client.post(
        "/management/organization",
        data={"name": "Rejected Organization"},
        headers={"Origin": TEST_ORIGIN},
        follow_redirects=False,
    )
    invalid = await client.post(
        "/management/organization",
        data={"name": "Rejected Organization", "csrf_token": "invalid"},
        headers={"Origin": TEST_ORIGIN},
        follow_redirects=False,
    )
    updated = await client.post(
        "/management/organization",
        data={"name": "Updated Organization", "csrf_token": csrf_token},
        headers={"Origin": TEST_ORIGIN},
        follow_redirects=False,
    )
    header_updated = await client.post(
        "/management/organization",
        data={"name": "Header Organization"},
        headers={
            "Origin": TEST_ORIGIN,
            app.state.settings.browser_session.csrf.header_name: csrf_token,
        },
        follow_redirects=False,
    )

    assert dashboard.status_code == status.HTTP_200_OK
    assert 'href="/management/organization/settings"' in dashboard.text
    assert 'id="organization-name"' not in dashboard.text
    assert page.status_code == status.HTTP_200_OK
    assert 'value="Test Organization"' in page.text
    assert missing.status_code == status.HTTP_403_FORBIDDEN
    assert missing.headers["content-type"].startswith("text/html")
    assert invalid.status_code == status.HTTP_403_FORBIDDEN
    assert invalid.headers["content-type"].startswith("text/html")
    assert updated.status_code == status.HTTP_303_SEE_OTHER
    assert updated.headers["location"].startswith("/management/organization?notice=")
    assert header_updated.status_code == status.HTTP_303_SEE_OTHER
    assert header_updated.headers["location"].startswith(
        "/management/organization?notice="
    )

    htmx_updated = await client.post(
        "/management/organization",
        data={"name": "HTMX Organization", "csrf_token": csrf_token},
        headers={"Origin": TEST_ORIGIN, "HX-Request": "true"},
    )
    assert htmx_updated.status_code == status.HTTP_204_NO_CONTENT
    assert htmx_updated.headers["HX-Redirect"].startswith(
        "/management/organization?notice="
    )


@pytest.mark.asyncio
async def test_organization_admin_can_manage_organization_security_sessions(
    client: httpx.AsyncClient,
    verified_user_credentials: UserCredentials,
) -> None:
    """Expose scoped organization session operations with confirmation."""
    await login_browser(client, verified_user_credentials)
    dashboard = await client.get("/management/organization")
    browser_url = "/management/organization/sessions/browser/delete"
    oauth2_url = "/management/organization/sessions/oauth2/delete"
    revoke_url = "/management/organization/sessions/revoke"

    assert f'href="{browser_url}"' in dashboard.text
    assert f'href="{oauth2_url}"' in dashboard.text
    assert f'href="{revoke_url}"' in dashboard.text
    assert "<h2>Delete browser sessions</h2>" in dashboard.text
    assert "<h2>Delete OAuth2 sessions</h2>" in dashboard.text
    assert "<h2>Revoke all sessions</h2>" in dashboard.text

    browser_confirm = await client.get(browser_url)
    oauth2_confirm = await client.get(oauth2_url)
    revoke_confirm = await client.get(revoke_url)
    retired_browser = await client.get(
        "/management/organization/browser-sessions/delete"
    )
    retired_oauth2 = await client.get("/management/organization/oauth2-sessions/delete")
    assert f'action="{browser_url}"' in browser_confirm.text
    assert "OAuth2 sessions are not affected." in browser_confirm.text
    assert f'action="{oauth2_url}"' in oauth2_confirm.text
    assert "Browser sessions are not affected." in oauth2_confirm.text
    assert f'action="{revoke_url}"' in revoke_confirm.text
    assert retired_browser.status_code == status.HTTP_404_NOT_FOUND
    assert retired_oauth2.status_code == status.HTTP_404_NOT_FOUND

    deleted = await client.post(
        oauth2_url,
        data={"confirm": "true", "csrf_token": _csrf(oauth2_confirm)},
        headers={"Origin": TEST_ORIGIN},
        follow_redirects=False,
    )

    assert deleted.status_code == status.HTTP_303_SEE_OTHER
    assert deleted.headers["location"].startswith("/management/organization?notice=")


@pytest.mark.asyncio
async def test_operator_can_manage_full_server_security_sessions(
    client: httpx.AsyncClient,
    verified_user_credentials: UserCredentials,
) -> None:
    """Expose the three global session operations with confirmation."""
    await login_browser(client, verified_user_credentials)
    page = await client.get("/management/operator/sessions")
    browser_url = "/management/operator/sessions/browser/delete"
    oauth2_url = "/management/operator/sessions/oauth2/delete"
    revoke_url = "/management/operator/sessions/revoke"

    assert f'href="{browser_url}"' in page.text
    assert f'href="{oauth2_url}"' in page.text
    assert f'href="{revoke_url}"' in page.text
    assert "<h2>Delete all browser sessions</h2>" in page.text
    assert "<h2>Delete all OAuth2 sessions</h2>" in page.text
    assert "<h2>Revoke all sessions</h2>" in page.text

    browser_confirm = await client.get(browser_url)
    oauth2_confirm = await client.get(oauth2_url)
    revoke_confirm = await client.get(revoke_url)
    assert f'action="{browser_url}"' in browser_confirm.text
    assert "across the entire server" in browser_confirm.text
    assert f'action="{oauth2_url}"' in oauth2_confirm.text
    assert "Browser sessions are not affected." in oauth2_confirm.text
    assert f'action="{revoke_url}"' in revoke_confirm.text

    deleted = await client.post(
        oauth2_url,
        data={"confirm": "true", "csrf_token": _csrf(oauth2_confirm)},
        headers={"Origin": TEST_ORIGIN},
        follow_redirects=False,
    )

    assert deleted.status_code == status.HTTP_303_SEE_OTHER
    assert deleted.headers["location"].startswith(
        "/management/operator/sessions?notice="
    )


@pytest.mark.asyncio
async def test_user_management_pages_link_to_scoped_session_actions(
    client: httpx.AsyncClient,
    verified_user_credentials: UserCredentials,
) -> None:
    """Place the three user-session actions after deletion on both edit pages."""
    await login_browser(client, verified_user_credentials)
    user_id = await _create_session_target(client)
    organization_users = await client.get(
        "/management/organization/users", params={"q": "session-target"}
    )
    organization_user_url = f"/management/organization/users/{user_id}"
    operator_user_url = f"/management/operator/users/{user_id}"
    organization_sessions_url = f"{organization_user_url}/sessions"
    operator_sessions_url = f"{operator_user_url}/sessions"
    server_users = await client.get(
        "/management/operator/users", params={"q": "session-target"}
    )

    assert ">Manage sessions</a>" not in organization_users.text
    assert ">Manage sessions</a>" not in server_users.text

    organization_user = await client.get(organization_user_url)
    operator_user = await client.get(operator_user_url)
    for page, user_path, sessions_path in (
        (organization_user, organization_user_url, organization_sessions_url),
        (operator_user, operator_user_url, operator_sessions_url),
    ):
        assert page.status_code == status.HTTP_200_OK
        delete_link = f'href="{user_path}/delete"'
        browser_link = f'href="{sessions_path}/browser/delete"'
        oauth2_link = f'href="{sessions_path}/oauth2/delete"'
        revoke_link = f'href="{sessions_path}/revoke"'
        assert page.text.index(delete_link) < page.text.index(browser_link)
        assert page.text.index(browser_link) < page.text.index(oauth2_link)
        assert page.text.index(oauth2_link) < page.text.index(revoke_link)
        assert "session-target@example.com" in page.text

    oauth2_confirm = await client.get(f"{organization_sessions_url}/oauth2/delete")
    deleted = await client.post(
        f"{organization_sessions_url}/oauth2/delete",
        data={"confirm": "true", "csrf_token": _csrf(oauth2_confirm)},
        headers={"Origin": TEST_ORIGIN},
        follow_redirects=False,
    )
    assert deleted.status_code == status.HTTP_303_SEE_OTHER
    assert deleted.headers["location"].startswith(f"{organization_user_url}?notice=")


@pytest.mark.asyncio
@pytest.mark.parametrize("prefix", ["/management/organization", "/management/operator"])
@pytest.mark.parametrize(
    ("action", "heading", "message", "submit_label"),
    [
        (
            "browser/delete",
            "Delete user browser sessions?",
            "OAuth2 sessions are not affected.",
            "Delete browser sessions",
        ),
        (
            "oauth2/delete",
            "Delete user OAuth2 sessions?",
            "Browser sessions are not affected.",
            "Delete OAuth2 sessions",
        ),
        (
            "revoke",
            "Revoke all user sessions?",
            "This ends browser and OAuth2 sessions",
            "Revoke all sessions",
        ),
    ],
)
async def test_scoped_user_session_actions_share_the_same_http_contract(  # noqa: PLR0913, PLR0917
    client: httpx.AsyncClient,
    verified_user_credentials: UserCredentials,
    prefix: str,
    action: str,
    heading: str,
    message: str,
    submit_label: str,
) -> None:
    """Preserve confirmation and mutation behavior for both actor scopes."""
    await login_browser(client, verified_user_credentials)
    user_id = await _create_session_target(client)
    user_path = f"{prefix}/users/{user_id}"
    action_url = f"{user_path}/sessions/{action}"

    confirmation = await client.get(action_url)

    assert confirmation.status_code == status.HTTP_200_OK
    assert f"<h1>{heading}</h1>" in confirmation.text
    assert message in confirmation.text
    assert f'action="{action_url}"' in confirmation.text
    assert f'href="{user_path}">Cancel</a>' in confirmation.text
    assert f">{submit_label}</button>" in confirmation.text

    response = await client.post(
        action_url,
        data={"confirm": "true", "csrf_token": _csrf(confirmation)},
        headers={"Origin": TEST_ORIGIN},
        follow_redirects=False,
    )

    assert response.status_code == status.HTTP_303_SEE_OTHER
    assert response.headers["location"].startswith(f"{user_path}?notice=")
    assert (await client.get("/management/operator")).status_code == status.HTTP_200_OK


@pytest.mark.asyncio
@with_external_management_presentation()
@pytest.mark.parametrize("action", ["browser/delete", "revoke"])
async def test_operator_user_session_actions_end_its_own_login(
    app: FastAPI,
    client: httpx.AsyncClient,
    verified_user_credentials: UserCredentials,
    action: str,
) -> None:
    """Clear the current cookie when an operator revokes its own authority."""
    await login_browser(client, verified_user_credentials)
    users = await client.get(
        "/management/operator/users", params={"q": verified_user_credentials.email}
    )
    user_match = re.search(
        rf'href="/management/operator/users/({UUID4_PATTERN})"', users.text
    )
    assert user_match is not None
    action_url = f"/management/operator/users/{user_match.group(1)}/sessions/{action}"
    confirmation = await client.get(action_url)

    response = await client.post(
        action_url,
        data={"confirm": "true", "csrf_token": _csrf(confirmation)},
        headers={"Origin": TEST_ORIGIN},
        follow_redirects=False,
    )

    assert response.status_code == status.HTTP_303_SEE_OTHER
    assert response.headers["location"].startswith(
        "https://frontend.test/login?notice="
    )
    assert any(
        cookie.startswith(f"{app.state.settings.browser_session.cookie_name}=")
        and "Max-Age=0" in cookie
        for cookie in response.headers.get_list("set-cookie")
    )
    protected = await client.get("/management/operator", follow_redirects=False)
    assert protected.status_code == status.HTTP_303_SEE_OTHER
