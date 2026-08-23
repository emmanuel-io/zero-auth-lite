"""Black-box HTTP tests for browser-session logout."""

import httpx
import pytest
from app.api.v1.browser_sessions import router as browser_session_router
from app.db.models.browser_session import BrowserSessionDB
from fastapi import FastAPI, status
from sqlalchemy import select

from tests.fixtures.auth import login_browser, UserCredentials
from tests.fixtures.settings import app_settings
from tests.routes.api.helpers import commit_failure_client


pytestmark = pytest.mark.api

TEST_ORIGIN = "http://testserver"


async def login(
    client: httpx.AsyncClient,
    credentials: UserCredentials,
) -> httpx.Response:
    """Log in the seeded browser-session user."""
    return await login_browser(client, credentials)


@pytest.mark.asyncio
@pytest.mark.system
async def test_logout_revokes_a_persisted_session_and_clears_cookies(
    app: FastAPI,
    client: httpx.AsyncClient,
    verified_user_credentials: UserCredentials,
) -> None:
    """Assert logout clears the browser cookie and revokes storage."""
    login_response = await login(client, verified_user_credentials)
    csrf_header_name = app.state.settings.session.csrf.header_name
    session_cookie_name = app.state.settings.session.cookie_name

    response = await client.post(
        "/api/v1/sessions/logout",
        headers={
            "Origin": TEST_ORIGIN,
            csrf_header_name: login_response.headers[csrf_header_name],
        },
    )

    assert response.status_code == status.HTTP_204_NO_CONTENT
    assert response.content == b""
    assert response.cookies.get(session_cookie_name) is None

    async with app.state.core_session_factory() as db_session:
        revoked_reason = await db_session.scalar(
            select(BrowserSessionDB.revoked_reason)
        )

    assert revoked_reason == "logout"


@pytest.mark.asyncio
@pytest.mark.negative
async def test_logout_commit_failure_keeps_cookie_and_session_authority(
    app: FastAPI,
    client: httpx.AsyncClient,
    verified_user_credentials: UserCredentials,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Keep browser and SQL authority aligned when logout cannot commit."""
    logged_messages: list[str] = []
    monkeypatch.setattr(
        browser_session_router.logger,
        "info",
        lambda message, *_args: logged_messages.append(message),
    )
    login_response = await login(client, verified_user_credentials)
    csrf_header_name = app.state.settings.session.csrf.header_name
    session_cookie_name = app.state.settings.session.cookie_name

    async with commit_failure_client(app, client) as failing_client:
        response = await failing_client.post(
            "/api/v1/sessions/logout",
            headers={
                "Origin": TEST_ORIGIN,
                csrf_header_name: login_response.headers[csrf_header_name],
            },
        )

        assert failing_client.cookies.get(session_cookie_name) is not None

    async with app.state.core_session_factory() as db_session:
        revoked_at = await db_session.scalar(select(BrowserSessionDB.revoked_at))

    assert response.status_code == status.HTTP_500_INTERNAL_SERVER_ERROR
    assert not any(
        header.startswith(f"{session_cookie_name}=")
        for header in response.headers.get_list("set-cookie")
    )
    assert revoked_at is None
    assert any(
        "event=browser_session_revocation outcome=attempted" in message
        for message in logged_messages
    )
    assert not any(
        "event=browser_session_revocation outcome=success" in message
        for message in logged_messages
    )


@pytest.mark.asyncio
async def test_logout_without_a_session_is_idempotent(
    client: httpx.AsyncClient,
) -> None:
    """Assert logout succeeds even when there is no browser session cookie."""
    response = await client.post("/api/v1/sessions/logout")

    assert response.status_code == status.HTTP_204_NO_CONTENT
    assert response.content == b""


@pytest.mark.asyncio
async def test_logout_with_an_invalid_session_cookie_is_idempotent(
    app: FastAPI,
    client: httpx.AsyncClient,
) -> None:
    """Assert stale session credentials can be cleared without CSRF proof."""
    session_cookie_name = app.state.settings.session.cookie_name
    client.cookies.set(session_cookie_name, "invalid-session")

    response = await client.post("/api/v1/sessions/logout")

    assert response.status_code == status.HTTP_204_NO_CONTENT
    assert response.content == b""
    assert any(
        session_cookie_name in header and "Max-Age=0" in header
        for header in response.headers.get_list("set-cookie")
    )


@pytest.mark.asyncio
@app_settings(session={"csrf": {"pattern": "double_submit"}})
async def test_logout_accepts_double_submit_csrf_state(
    app: FastAPI,
    client: httpx.AsyncClient,
    verified_user_credentials: UserCredentials,
) -> None:
    """Assert configured double-submit CSRF state can authorize logout."""
    login_response = await login(client, verified_user_credentials)
    csrf_settings = app.state.settings.session.csrf

    response = await client.post(
        "/api/v1/sessions/logout",
        headers={
            "Origin": TEST_ORIGIN,
            csrf_settings.header_name: login_response.headers[
                csrf_settings.header_name
            ],
        },
    )

    assert response.status_code == status.HTTP_204_NO_CONTENT
    async with app.state.core_session_factory() as db_session:
        revoked_reason = await db_session.scalar(
            select(BrowserSessionDB.revoked_reason)
        )
    assert revoked_reason == "logout"


@pytest.mark.asyncio
@pytest.mark.negative
async def test_logout_rejects_missing_csrf_proof(
    client: httpx.AsyncClient,
    verified_user_credentials: UserCredentials,
) -> None:
    """Assert valid sessions still require CSRF proof for logout."""
    login_response = await login(client, verified_user_credentials)

    response = await client.post(
        "/api/v1/sessions/logout",
        headers={"Origin": TEST_ORIGIN},
    )

    assert response.status_code == status.HTTP_403_FORBIDDEN
    assert response.json()["message"] == "CSRF header missing"
    assert login_response.status_code == status.HTTP_204_NO_CONTENT


@pytest.mark.asyncio
@pytest.mark.negative
async def test_logout_rejects_csrf_not_bound_to_the_session(
    app: FastAPI,
    client: httpx.AsyncClient,
    verified_user_credentials: UserCredentials,
) -> None:
    """Assert synchronizer CSRF proof must match the persisted session."""
    await login(client, verified_user_credentials)
    csrf_header_name = app.state.settings.session.csrf.header_name

    response = await client.post(
        "/api/v1/sessions/logout",
        headers={
            "Origin": TEST_ORIGIN,
            csrf_header_name: "csrf-for-a-different-session",
        },
    )

    assert response.status_code == status.HTTP_403_FORBIDDEN
    assert response.json()["message"] == "CSRF header session mismatch"


@pytest.mark.asyncio
@pytest.mark.negative
async def test_logout_rejects_untrusted_origins(
    app: FastAPI,
    client: httpx.AsyncClient,
    verified_user_credentials: UserCredentials,
) -> None:
    """Assert logout rejects origins outside the configured trust set."""
    login_response = await login(client, verified_user_credentials)
    csrf_header_name = app.state.settings.session.csrf.header_name

    response = await client.post(
        "/api/v1/sessions/logout",
        headers={
            "Origin": "https://attacker.example",
            csrf_header_name: login_response.headers[csrf_header_name],
        },
    )

    assert response.status_code == status.HTTP_403_FORBIDDEN
    assert response.json()["message"] == "CSRF cookie header mismatch"


@pytest.mark.asyncio
@pytest.mark.negative
async def test_a_revoked_session_cannot_authenticate_again(
    app: FastAPI,
    client: httpx.AsyncClient,
    verified_user_credentials: UserCredentials,
) -> None:
    """Assert a logged-out session no longer passes browser-session auth."""
    login_response = await login(client, verified_user_credentials)
    csrf_header_name = app.state.settings.session.csrf.header_name
    session_cookie_name = app.state.settings.session.cookie_name
    session_id = login_response.cookies[session_cookie_name]
    csrf_token = login_response.headers[csrf_header_name]

    logout_response = await client.post(
        "/api/v1/sessions/logout",
        headers={
            "Origin": TEST_ORIGIN,
            csrf_header_name: csrf_token,
        },
    )
    client.cookies.set(
        session_cookie_name,
        session_id,
        domain="testserver",
        path="/",
    )

    csrf_response = await client.get("/api/v1/sessions/csrf")
    protected_response = await client.get("/api/v1/me")

    assert logout_response.status_code == status.HTTP_204_NO_CONTENT
    assert csrf_response.status_code == status.HTTP_204_NO_CONTENT
    assert protected_response.status_code == status.HTTP_401_UNAUTHORIZED
