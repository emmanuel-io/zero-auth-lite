"""Black-box HTTP tests for browser-session CSRF handling."""

import httpx
import pytest
from app.db.models.user import UserDB
from fastapi import FastAPI, status
from sqlalchemy import update

from tests.fixtures.auth import (
    current_user_id_for_email,
    login_browser,
    UserCredentials,
)
from tests.fixtures.routes import BrowserClientFactory
from tests.fixtures.settings import app_settings


pytestmark = pytest.mark.api


async def login(
    client: httpx.AsyncClient,
    credentials: UserCredentials,
) -> httpx.Response:
    """Log in the seeded browser-session user."""
    return await login_browser(client, credentials)


@pytest.mark.asyncio
async def test_csrf_exposes_header_without_reissuing_the_session_cookie(
    app: FastAPI,
    client: httpx.AsyncClient,
    verified_user_credentials: UserCredentials,
) -> None:
    """Fetch CSRF state without reissuing an unchanged session cookie."""
    login_response = await login(client, verified_user_credentials)
    csrf_header_name = app.state.settings.session.csrf.header_name
    session_cookie_name = app.state.settings.session.cookie_name

    response = await client.get("/api/v1/sessions/csrf")

    assert response.status_code == status.HTTP_204_NO_CONTENT
    assert (
        response.headers[csrf_header_name] == login_response.headers[csrf_header_name]
    )
    assert session_cookie_name not in response.cookies


@pytest.mark.asyncio
@app_settings(
    session={
        "absolute_ttl_seconds": 240,
        "slide_seconds": 120,
        "ttl_seconds": 120,
        "csrf": {"expose_token": "cookie"},
    }
)
async def test_csrf_cookie_refresh_uses_the_persisted_session_lifetime(
    app: FastAPI,
    client: httpx.AsyncClient,
    verified_user_credentials: UserCredentials,
) -> None:
    """Assert refreshed CSRF cookies cannot outlive persisted sessions."""
    await login(client, verified_user_credentials)
    csrf_settings = app.state.settings.session.csrf

    response = await client.get("/api/v1/sessions/csrf")

    csrf_cookie_header = next(
        header
        for header in response.headers.get_list("set-cookie")
        if header.startswith(f"{csrf_settings.cookie_name}=")
    )
    max_age = int(csrf_cookie_header.split("Max-Age=", 1)[1].split(";", 1)[0])
    assert response.status_code == status.HTTP_204_NO_CONTENT
    assert csrf_settings.header_name not in response.headers
    assert "HttpOnly" not in csrf_cookie_header
    assert 0 < max_age <= app.state.settings.session.ttl_seconds


@pytest.mark.asyncio
@pytest.mark.negative
async def test_csrf_issues_stateless_pre_session_state(
    app: FastAPI,
    client: httpx.AsyncClient,
) -> None:
    """Assert anonymous callers receive CSRF state without a session."""
    response = await client.get("/api/v1/sessions/csrf")

    csrf_settings = app.state.settings.session.csrf
    assert response.status_code == status.HTTP_204_NO_CONTENT
    assert response.headers["Cache-Control"] == "no-store"
    assert (
        response.cookies[csrf_settings.cookie_name]
        == response.headers[csrf_settings.header_name]
    )
    assert app.state.settings.session.cookie_name not in response.cookies


@pytest.mark.asyncio
@pytest.mark.negative
async def test_csrf_ignores_a_bearer_token_and_issues_pre_session_state(
    app: FastAPI,
    browser_client_factory: BrowserClientFactory,
) -> None:
    """Assert bearer authentication does not change pre-session CSRF behavior."""
    async with browser_client_factory() as bearer_client:
        response = await bearer_client.get(
            "/api/v1/sessions/csrf",
            headers={"Authorization": "Bearer irrelevant-for-this-endpoint"},
        )

    csrf_settings = app.state.settings.session.csrf
    assert response.status_code == status.HTTP_204_NO_CONTENT
    assert (
        response.cookies[csrf_settings.cookie_name]
        == response.headers[csrf_settings.header_name]
    )


@pytest.mark.asyncio
async def test_csrf_recovers_from_an_invalid_session_cookie(
    app: FastAPI,
    client: httpx.AsyncClient,
) -> None:
    """Assert stale browser sessions fall back to fresh pre-session CSRF state."""
    session_settings = app.state.settings.session
    client.cookies.set(session_settings.cookie_name, "invalid-session")

    response = await client.get("/api/v1/sessions/csrf")

    set_cookie_headers = response.headers.get_list("set-cookie")
    assert response.status_code == status.HTTP_204_NO_CONTENT
    assert any(
        session_settings.cookie_name in header and "Max-Age=0" in header
        for header in set_cookie_headers
    )
    assert (
        response.cookies[session_settings.csrf.cookie_name]
        == response.headers[session_settings.csrf.header_name]
    )


@pytest.mark.asyncio
@pytest.mark.negative
async def test_csrf_replaces_a_session_for_an_inactive_user(
    app: FastAPI,
    client: httpx.AsyncClient,
    verified_user_credentials: UserCredentials,
) -> None:
    """Do not renew browser authority after its user becomes inactive."""
    login_response = await login(client, verified_user_credentials)
    assert login_response.status_code == status.HTTP_204_NO_CONTENT
    async with app.state.core_session_factory() as db_session:
        await db_session.execute(
            update(UserDB)
            .where(
                UserDB.id == current_user_id_for_email(verified_user_credentials.email)
            )
            .values(is_active=False)
        )
        await db_session.commit()

    response = await client.get("/api/v1/sessions/csrf")

    settings = app.state.settings.session
    set_cookie_headers = response.headers.get_list("set-cookie")
    assert response.status_code == status.HTTP_204_NO_CONTENT
    assert any(
        header.startswith(f"{settings.cookie_name}=") and "Max-Age=0" in header
        for header in set_cookie_headers
    )
    assert (
        response.cookies[settings.csrf.cookie_name]
        == response.headers[settings.csrf.header_name]
    )
