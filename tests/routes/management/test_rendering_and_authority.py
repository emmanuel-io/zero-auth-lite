"""Shared management rendering, validation, and authority route tests."""

import re

import httpx
import pytest
from app.db.models.organization_membership import OrganizationMembershipDB
from app.db.models.user import UserDB
from app.identity.users.enums import OrganizationMembershipRole
from app.oauth2.specs import OAuth2Specs
from fastapi import FastAPI, status
from sqlalchemy import update

from tests.fixtures.auth import issue_user_token, login_browser, UserCredentials
from tests.identifiers import deterministic_uuid, UUID4_PATTERN


pytestmark = pytest.mark.api
TEST_ORIGIN = "http://testserver"


def _csrf(response: httpx.Response) -> str:
    match = re.search(r'name="csrf_token" value="([^"]+)"', response.text)
    assert match is not None
    return match.group(1)


@pytest.mark.asyncio
async def test_management_notices_resolve_only_server_owned_codes(
    client: httpx.AsyncClient,
    verified_user_credentials: UserCredentials,
) -> None:
    """Render known result codes without echoing arbitrary query text."""
    await login_browser(client, verified_user_credentials)

    known = await client.get(
        "/management/account", params={"notice": "profile-updated"}
    )
    unknown = await client.get(
        "/management/account", params={"notice": "Account access granted."}
    )

    assert '<div class="notice" role="status">Profile updated.</div>' in known.text
    assert "Account access granted." not in unknown.text
    assert '<div class="notice" role="status">' not in unknown.text


@pytest.mark.asyncio
@pytest.mark.negative
@pytest.mark.parametrize("headers", [{}, {"HX-Request": "true"}])
async def test_unknown_management_path_renders_html(
    client: httpx.AsyncClient,
    headers: dict[str, str],
) -> None:
    """Keep unmatched management URLs inside the HTML transport boundary."""
    response = await client.get("/management/not-a-page", headers=headers)

    assert response.status_code == status.HTTP_404_NOT_FOUND
    assert response.headers["content-type"].startswith("text/html")
    assert "Request unavailable" in response.text
    assert ("<!doctype html>" in response.text) is not bool(headers)


@pytest.mark.asyncio
@pytest.mark.negative
async def test_management_forms_render_domain_validation_as_html(
    client: httpx.AsyncClient,
    verified_user_credentials: UserCredentials,
) -> None:
    """Reject invalid domain values at the HTML transport boundary."""
    await login_browser(client, verified_user_credentials)
    organization_page = await client.get("/management/organization/settings")
    user_page = await client.get("/management/organization/users/new")
    client_page = await client.get("/management/operator/oauth2/clients/new")

    invalid_organization = await client.post(
        "/management/organization",
        data={"name": "x" * 33, "csrf_token": _csrf(organization_page)},
        headers={"Origin": TEST_ORIGIN},
    )
    invalid_client = await client.post(
        "/management/operator/oauth2/clients",
        data={
            "name": "x" * 101,
            "grant_types": "client_credentials",
            "scopes": "s" * 49,
            "redirect_uris": "https://example.test/" + "x" * 300,
            "user_organization_access": "unrestricted",
            "csrf_token": _csrf(client_page),
        },
        headers={"Origin": TEST_ORIGIN, "HX-Request": "true"},
    )
    invalid_user = await client.post(
        "/management/organization/users",
        data={
            "email": "not-an-email",
            "first_name": "x" * 65,
            "last_name": "User",
            "role": "member",
            "csrf_token": _csrf(user_page),
        },
        headers={"Origin": TEST_ORIGIN},
    )
    invalid_password = await client.post(
        "/management/organization/users",
        data={
            "email": "weak-password@example.com",
            "password": "weak",
            "role": "member",
            "csrf_token": _csrf(user_page),
        },
        headers={"Origin": TEST_ORIGIN},
    )
    invalid_public_id = await client.get("/management/operator/organizations/not-an-id")

    for response in (
        invalid_organization,
        invalid_client,
        invalid_user,
        invalid_password,
        invalid_public_id,
    ):
        assert response.status_code == status.HTTP_422_UNPROCESSABLE_CONTENT
        assert response.headers["content-type"].startswith("text/html")
        assert "Check the submitted values" in response.text
    assert "<!doctype html>" not in invalid_client.text


@pytest.mark.asyncio
@pytest.mark.negative
async def test_management_identifier_validation_uses_typed_inputs(
    client: httpx.AsyncClient,
    verified_user_credentials: UserCredentials,
) -> None:
    """Render invalid query and form UUIDs through the HTML error boundary."""
    await login_browser(client, verified_user_credentials)
    operator_user_page = await client.get("/management/operator/users/new")

    invalid_organization_filter = await client.get(
        "/management/operator/users",
        params={"organization_id": "not-an-id"},
    )
    invalid_user_filter = await client.get(
        "/management/organization/oauth2/sessions",
        params={"user_id": "not-an-id"},
    )
    invalid_client_filter = await client.get(
        "/management/organization/oauth2/sessions",
        params={"client_id": "not-an-id"},
        headers={"HX-Request": "true"},
    )
    invalid_organization_form = await client.post(
        "/management/operator/users",
        data={
            "email": "typed-id@example.com",
            "organization_id": "not-an-id",
            "role": "member",
            "csrf_token": _csrf(operator_user_page),
        },
        headers={"Origin": TEST_ORIGIN},
    )

    for response in (
        invalid_organization_filter,
        invalid_user_filter,
        invalid_client_filter,
        invalid_organization_form,
    ):
        assert response.status_code == status.HTTP_422_UNPROCESSABLE_CONTENT
        assert response.headers["content-type"].startswith("text/html")
        assert "Check the submitted values" in response.text
    assert "<!doctype html>" not in invalid_client_filter.text


@pytest.mark.asyncio
@pytest.mark.negative
async def test_oauth2_client_form_validates_organization_id_lines_in_dto(
    client: httpx.AsyncClient,
    verified_user_credentials: UserCredentials,
) -> None:
    """Reject invalid and excessive organization assignments in the DTO."""
    await login_browser(client, verified_user_credentials)
    client_page = await client.get("/management/operator/oauth2/clients/new")
    form = {
        "name": "Organization-filtered client",
        "grant_types": "client_credentials",
        "user_organization_access": "selected",
        "csrf_token": _csrf(client_page),
    }

    invalid_id = await client.post(
        "/management/operator/oauth2/clients",
        data={**form, "organization_ids": "not-an-id"},
        headers={"Origin": TEST_ORIGIN, "HX-Request": "true"},
    )
    too_many_ids = await client.post(
        "/management/operator/oauth2/clients",
        data={
            **form,
            "organization_ids": "\n".join(
                str(deterministic_uuid(index))
                for index in range(
                    OAuth2Specs.CLIENT_ORGANIZATION_ASSIGNMENTS_MAX + 1
                )
            ),
        },
        headers={"Origin": TEST_ORIGIN},
    )

    for response in (invalid_id, too_many_ids):
        assert response.status_code == status.HTTP_422_UNPROCESSABLE_CONTENT
        assert response.headers["content-type"].startswith("text/html")
        assert "Check the submitted values" in response.text
    assert "<!doctype html>" not in invalid_id.text


@pytest.mark.asyncio
@pytest.mark.negative
async def test_oauth2_client_form_rejects_unsafe_redirect_uri(
    client: httpx.AsyncClient,
    verified_user_credentials: UserCredentials,
) -> None:
    """Apply the canonical redirect URI policy to the HTML adapter."""
    await login_browser(client, verified_user_credentials)
    client_page = await client.get("/management/operator/oauth2/clients/new")

    response = await client.post(
        "/management/operator/oauth2/clients",
        data={
            "name": "Unsafe client",
            "grant_types": "authorization_code",
            "redirect_uris": "https://client.example/callback#fragment",
            "user_organization_access": "unrestricted",
            "csrf_token": _csrf(client_page),
        },
        headers={"Origin": TEST_ORIGIN, "HX-Request": "true"},
    )

    assert response.status_code == status.HTTP_400_BAD_REQUEST
    assert response.headers["content-type"].startswith("text/html")
    assert "Redirect URIs must not contain a fragment." in response.text


@pytest.mark.asyncio
async def test_management_resource_pages_render_with_enabled_features(
    app: FastAPI,
    client: httpx.AsyncClient,
    verified_user_credentials: UserCredentials,
) -> None:
    """Smoke-test each list and detail surface with the canonical seeded state."""
    await login_browser(client, verified_user_credentials)
    form = await client.get("/management/operator/oauth2/clients/new")
    created = await client.post(
        "/management/operator/oauth2/clients",
        data={
            "name": "Smoke-test client",
            "grant_types": "client_credentials",
            "scopes": "users:read",
            "redirect_uris": "",
            "is_confidential": "true",
            "is_active": "true",
            "user_organization_access": "unrestricted",
            "csrf_token": _csrf(form),
        },
        headers={"Origin": TEST_ORIGIN},
    )
    assert created.status_code == status.HTTP_200_OK
    token_response = await issue_user_token(app, client, verified_user_credentials)
    assert token_response.status_code == status.HTTP_200_OK
    detail_match = re.search(
        r'href="(/management/operator/oauth2/clients/[^"]+)"', created.text
    )
    assert detail_match is not None

    paths = (
        "/management/organization/users",
        "/management/organization/oauth2/sessions",
        "/management/operator/organizations",
        "/management/operator/users",
        "/management/operator/sessions",
        "/management/operator/oauth2/clients",
        detail_match.group(1),
    )
    responses = [await client.get(path) for path in paths]

    assert [response.status_code for response in responses] == [
        status.HTTP_200_OK
    ] * len(paths)
    assert re.search(UUID4_PATTERN, responses[1].text)
    assert "read" in responses[1].text


@pytest.mark.asyncio
async def test_htmx_filter_returns_only_the_replaceable_fragment(
    client: httpx.AsyncClient,
    verified_user_credentials: UserCredentials,
) -> None:
    """Avoid returning the management document shell for htmx list refreshes."""
    await login_browser(client, verified_user_credentials)

    response = await client.get(
        "/management/organization/users",
        headers={"HX-Request": "true"},
    )

    assert response.status_code == status.HTTP_200_OK
    assert '<div id="user-results">' in response.text
    assert "<!doctype html>" not in response.text
    assert "htmx-4.0.0-beta6.min.js" not in response.text


@pytest.mark.asyncio
async def test_management_authority_is_reloaded_from_current_identity_state(
    app: FastAPI,
    client: httpx.AsyncClient,
    verified_user_credentials: UserCredentials,
) -> None:
    """Deny both interfaces immediately after their server-side roles are removed."""
    await login_browser(client, verified_user_credentials)
    async with app.state.core_session_factory.begin() as session:
        await session.execute(
            update(OrganizationMembershipDB).values(
                role=OrganizationMembershipRole.MEMBER
            )
        )
        await session.execute(update(UserDB).values(is_operator=False))

    organization = await client.get("/management/organization")
    operator = await client.get("/management/operator")

    assert organization.status_code == status.HTTP_403_FORBIDDEN
    assert operator.status_code == status.HTTP_403_FORBIDDEN
    assert "Request unavailable" in organization.text
    assert "Request unavailable" in operator.text
