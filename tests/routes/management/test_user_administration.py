"""Management user and organization form route tests."""

import re
from datetime import datetime, UTC

import httpx
import pytest
from app.db.models.user import UserDB, UserEmailDB
from app.identity.users.enums import UserEmailStatus
from fastapi import FastAPI, status
from sqlalchemy import select, update

from tests.fixtures.auth import login_browser, UserCredentials
from tests.identifiers import (
    parse_public_id as parse_user_id,
    UUID4_PATTERN,
    UUID4_VERSION,
)


pytestmark = pytest.mark.api
TEST_ORIGIN = "http://testserver"


def _csrf(response: httpx.Response) -> str:
    match = re.search(r'name="csrf_token" value="([^"]+)"', response.text)
    assert match is not None
    return match.group(1)


@pytest.mark.asyncio
@pytest.mark.negative
@pytest.mark.parametrize(
    "path",
    ["/management/organization/users", "/management/operator/users"],
)
async def test_management_user_search_rejects_oversized_query(
    client: httpx.AsyncClient,
    verified_user_credentials: UserCredentials,
    path: str,
) -> None:
    """Render the management validation error for oversized searches."""
    await login_browser(client, verified_user_credentials)

    response = await client.get(path, params={"q": "x" * 257})

    assert response.status_code == status.HTTP_422_UNPROCESSABLE_CONTENT
    assert response.headers["content-type"].startswith("text/html")
    assert "Check the submitted values" in response.text


@pytest.mark.asyncio
async def test_organization_admin_can_invite_user_from_html_form(
    client: httpx.AsyncClient,
    verified_user_credentials: UserCredentials,
) -> None:
    """Drive organization-user lifecycle services through the HTML adapter."""
    await login_browser(client, verified_user_credentials)
    form = await client.get("/management/organization/users/new")

    created = await client.post(
        "/management/organization/users",
        data={
            "email": "invited@example.com",
            "first_name": "Invited",
            "last_name": "User",
            "role": "member",
            "is_active": "true",
            "csrf_token": _csrf(form),
        },
        headers={"Origin": TEST_ORIGIN},
        follow_redirects=False,
    )
    users = await client.get("/management/organization/users", params={"q": "invited"})

    assert created.status_code == status.HTTP_303_SEE_OTHER
    assert "invited@example.com" in users.text


@pytest.mark.asyncio
async def test_invitation_action_matches_user_lifecycle_state(
    app: FastAPI,
    client: httpx.AsyncClient,
    verified_user_credentials: UserCredentials,
) -> None:
    """Offer resend only for active, unverified users and use a truthful notice."""
    await login_browser(client, verified_user_credentials)
    create_form = await client.get("/management/organization/users/new")
    await client.post(
        "/management/organization/users",
        data={
            "email": "invitation-state@example.com",
            "first_name": "Invitation",
            "last_name": "State",
            "role": "member",
            "is_active": "true",
            "csrf_token": _csrf(create_form),
        },
        headers={"Origin": TEST_ORIGIN},
    )
    users = await client.get(
        "/management/organization/users", params={"q": "invitation-state"}
    )
    target_match = re.search(
        rf'href="(/management/organization/users/{UUID4_PATTERN})"', users.text
    )
    assert target_match is not None
    organization_url = target_match.group(1)
    user_id = organization_url.rsplit("/", 1)[1]
    operator_url = f"/management/operator/users/{user_id}"

    for page in (
        await client.get(organization_url),
        await client.get(operator_url),
    ):
        assert "Resend invitation" in page.text

    async with app.state.core_session_factory.begin() as session:
        target_id = await session.scalar(
            select(UserDB.id).where(UserDB.public_id == parse_user_id(user_id))
        )
        assert target_id is not None
        await session.execute(
            update(UserEmailDB)
            .where(UserEmailDB.user_id == target_id)
            .where(UserEmailDB.status == UserEmailStatus.CURRENT)
            .values(verified_at=datetime.now(UTC))
        )

    for verified_url in (organization_url, operator_url):
        verified_page = await client.get(verified_url)
        assert "Resend invitation" not in verified_page.text
        processed = await client.post(
            f"{verified_url}/invitation",
            data={"csrf_token": _csrf(verified_page)},
            headers={"Origin": TEST_ORIGIN},
            follow_redirects=False,
        )
        assert processed.status_code == status.HTTP_303_SEE_OTHER
        assert processed.headers["location"].endswith("?notice=invitation-processed")

    async with app.state.core_session_factory.begin() as session:
        await session.execute(
            update(UserDB)
            .where(UserDB.public_id == parse_user_id(user_id))
            .values(is_active=False)
        )
        await session.execute(
            update(UserEmailDB)
            .where(UserEmailDB.user_id == target_id)
            .where(UserEmailDB.status == UserEmailStatus.CURRENT)
            .values(verified_at=None)
        )

    for page in (
        await client.get(organization_url),
        await client.get(operator_url),
    ):
        assert "Resend invitation" not in page.text


@pytest.mark.asyncio
async def test_operator_opens_organization_creation_from_the_list(
    client: httpx.AsyncClient,
    verified_user_credentials: UserCredentials,
) -> None:
    """Keep organization creation behind the list's primary action."""
    await login_browser(client, verified_user_credentials)

    organizations = await client.get("/management/operator/organizations")
    form = await client.get("/management/operator/organizations/new")

    assert organizations.status_code == status.HTTP_200_OK
    assert (
        'href="/management/operator/organizations/new">Create organization</a>'
        in organizations.text
    )
    assert 'action="/management/operator/organizations"' not in organizations.text
    assert form.status_code == status.HTTP_200_OK
    assert (
        '<form class="form-stack" method="post" '
        'action="/management/operator/organizations"' in form.text
    )

    created = await client.post(
        "/management/operator/organizations",
        data={"name": "Created Organization", "csrf_token": _csrf(form)},
        headers={"Origin": TEST_ORIGIN},
        follow_redirects=False,
    )

    assert created.status_code == status.HTTP_303_SEE_OTHER
    organization_id = created.headers["location"].split("?", 1)[0].rsplit("/", 1)[1]
    assert parse_user_id(organization_id).version == UUID4_VERSION


@pytest.mark.asyncio
async def test_user_forms_use_full_width_and_responsive_field_grids(
    client: httpx.AsyncClient,
    verified_user_credentials: UserCredentials,
) -> None:
    """Keep operator and organization user forms consistently responsive."""
    await login_browser(client, verified_user_credentials)
    server_users = await client.get("/management/operator/users")
    organization_users = await client.get("/management/organization/users")
    operator_match = re.search(
        rf'href="(/management/operator/users/{UUID4_PATTERN})"', server_users.text
    )
    organization_match = re.search(
        rf'href="(/management/organization/users/{UUID4_PATTERN})"',
        organization_users.text,
    )
    assert operator_match is not None
    assert organization_match is not None
    manage_button = 'class="button button--secondary button--compact"'
    assert manage_button in server_users.text
    assert manage_button in organization_users.text

    organization_create = await client.get("/management/organization/users/new")
    organization_edit = await client.get(organization_match.group(1))
    operator_create = await client.get("/management/operator/users/new")
    operator_edit = await client.get(operator_match.group(1))
    responses = [
        operator_create,
        operator_edit,
        organization_create,
        organization_edit,
    ]

    for response in responses:
        assert response.status_code == status.HTTP_200_OK
        assert 'class="panel form-panel form-panel--full"' in response.text
        assert 'class="form-field-grid"' in response.text
    for response in (operator_edit, organization_edit):
        assert 'class="inline-actions user-management-actions"' in response.text
    for response in (organization_create, organization_edit):
        assert '<option value="admin"' in response.text
        assert ">Admin</option>" in response.text
        assert "Organization admin</option>" not in response.text
    for response in (operator_create, operator_edit):
        assert response.text.index('for="email"') < response.text.index(
            'for="first-name"'
        )
        assert response.text.index('for="role"') < response.text.index(
            'for="organization-id"'
        )


@pytest.mark.asyncio
@pytest.mark.parametrize("surface", ["operator", "organization"])
@pytest.mark.parametrize("transport", ["prg", "htmx"])
async def test_user_deletion_confirmation_and_navigation(
    client: httpx.AsyncClient,
    verified_user_credentials: UserCredentials,
    surface: str,
    transport: str,
) -> None:
    """Preserve each surface's confirmation and PRG or htmx navigation."""
    await login_browser(client, verified_user_credentials)
    create_form = await client.get("/management/organization/users/new")
    email = f"delete-{surface}-{transport}@example.com"
    await client.post(
        "/management/organization/users",
        data={
            "email": email,
            "first_name": "Delete",
            "last_name": "Target",
            "role": "member",
            "is_active": "true",
            "csrf_token": _csrf(create_form),
        },
        headers={"Origin": TEST_ORIGIN},
    )
    users_url = f"/management/{surface}/users"
    users = await client.get(users_url, params={"q": email})
    user_match = re.search(rf'href="([^"]+/{UUID4_PATTERN})"', users.text)
    assert user_match is not None
    user_url = user_match.group(1)
    delete_url = f"{user_url}/delete"

    confirmation = await client.get(delete_url)

    title = (
        "Delete server user?" if surface == "operator" else "Delete organization user?"
    )
    assert f"<h1>{title}</h1>" in confirmation.text
    assert f"This permanently deletes {email}." in confirmation.text
    assert f'action="{delete_url}"' in confirmation.text
    assert f'href="{user_url}">Cancel</a>' in confirmation.text
    headers = {"Origin": TEST_ORIGIN}
    if transport == "htmx":
        headers["HX-Request"] = "true"

    deleted = await client.post(
        delete_url,
        data={"confirm": "true", "csrf_token": _csrf(confirmation)},
        headers=headers,
        follow_redirects=False,
    )

    expected_status = (
        status.HTTP_204_NO_CONTENT if transport == "htmx" else status.HTTP_303_SEE_OTHER
    )
    destination_header = "HX-Redirect" if transport == "htmx" else "location"
    assert deleted.status_code == expected_status
    assert deleted.headers[destination_header] == f"{users_url}?notice=user-deleted"
