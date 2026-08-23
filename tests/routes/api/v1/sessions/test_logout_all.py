"""Black-box HTTP tests for scoped browser-session logout."""

import httpx
import pytest
from app.db.models.browser_session import BrowserSessionDB
from fastapi import FastAPI, status
from sqlalchemy import func, select

from tests.fixtures.auth import login_browser, UserCredentials
from tests.fixtures.routes import BrowserClientFactory


pytestmark = pytest.mark.api

TEST_ORIGIN = "http://testserver"
EXPECTED_REVOKED_SESSION_COUNT = 2


async def login(
    client: httpx.AsyncClient,
    credentials: UserCredentials,
) -> httpx.Response:
    """Log in the seeded browser-session user."""
    return await login_browser(client, credentials)


@pytest.mark.asyncio
@pytest.mark.system
async def test_logout_all_revokes_both_sessions_and_clears_the_calling_client(
    app: FastAPI,
    browser_client_factory: BrowserClientFactory,
    verified_user_credentials: UserCredentials,
) -> None:
    """Assert the all scope revokes all sessions for the current user."""
    csrf_header_name = app.state.settings.session.csrf.header_name
    session_cookie_name = app.state.settings.session.cookie_name

    async with (
        browser_client_factory() as first_client,
        browser_client_factory() as second_client,
    ):
        first_login = await login(first_client, verified_user_credentials)
        second_login = await login(second_client, verified_user_credentials)
        assert second_login.status_code == status.HTTP_204_NO_CONTENT
        response = await first_client.post(
            "/api/v1/sessions/logout",
            json={"scope": "all"},
            headers={
                "Origin": TEST_ORIGIN,
                csrf_header_name: first_login.headers[csrf_header_name],
            },
        )
        deletion_headers = response.headers.get_list("set-cookie")
        csrf_response = await second_client.get("/api/v1/sessions/csrf")
        rejected_response = await second_client.get("/api/v1/me")

    async with app.state.core_session_factory() as db_session:
        revoked_count = await db_session.scalar(
            select(func.count())
            .select_from(BrowserSessionDB)
            .where(BrowserSessionDB.revoked_reason == "logout_all")
        )

    assert response.status_code == status.HTTP_204_NO_CONTENT
    assert response.content == b""
    assert any(
        header.startswith(f'{session_cookie_name}="";') and "Max-Age=0" in header
        for header in deletion_headers
    )
    assert revoked_count == EXPECTED_REVOKED_SESSION_COUNT
    assert csrf_response.status_code == status.HTTP_204_NO_CONTENT
    assert rejected_response.status_code == status.HTTP_401_UNAUTHORIZED


@pytest.mark.asyncio
@pytest.mark.negative
async def test_logout_all_requires_a_browser_session(
    client: httpx.AsyncClient,
) -> None:
    """Assert the all scope rejects unauthenticated requests."""
    response = await client.post("/api/v1/sessions/logout", json={"scope": "all"})

    assert response.status_code == status.HTTP_401_UNAUTHORIZED


@pytest.mark.asyncio
@pytest.mark.negative
async def test_logout_rejects_unknown_json_fields(
    client: httpx.AsyncClient,
) -> None:
    """Keep the versioned logout JSON contract strict."""
    response = await client.post(
        "/api/v1/sessions/logout",
        json={"scope": "all", "unexpected": True},
    )

    assert response.status_code == status.HTTP_422_UNPROCESSABLE_CONTENT


@pytest.mark.asyncio
@pytest.mark.system
async def test_logout_others_preserves_the_calling_session(
    app: FastAPI,
    browser_client_factory: BrowserClientFactory,
    verified_user_credentials: UserCredentials,
) -> None:
    """Assert the others scope revokes every session except the caller."""
    csrf_header_name = app.state.settings.session.csrf.header_name

    async with (
        browser_client_factory() as first_client,
        browser_client_factory() as second_client,
    ):
        first_login = await login(first_client, verified_user_credentials)
        await login(second_client, verified_user_credentials)
        response = await first_client.post(
            "/api/v1/sessions/logout",
            json={"scope": "others"},
            headers={
                "Origin": TEST_ORIGIN,
                csrf_header_name: first_login.headers[csrf_header_name],
            },
        )
        calling_session_response = await first_client.get("/api/v1/me")
        other_session_response = await second_client.get("/api/v1/me")

    assert response.status_code == status.HTTP_204_NO_CONTENT
    assert calling_session_response.status_code == status.HTTP_200_OK
    assert other_session_response.status_code == status.HTTP_401_UNAUTHORIZED
