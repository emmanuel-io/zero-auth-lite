"""Black-box tests for `/api/v1/me/sessions` administration."""

from datetime import datetime, timedelta, UTC

import httpx
import pytest
from app.db.models.browser_session import BrowserSessionDB
from fastapi import FastAPI, status
from sqlalchemy import update

from tests.fixtures.auth import issue_user_token, UserCredentials
from tests.fixtures.routes import BrowserClientFactory
from tests.identifiers import (
    parse_public_id as parse_browser_session_id,
    UUID4_VERSION,
)
from tests.routes.api.helpers import login_headers


pytestmark = pytest.mark.api

SESSIONS_PATH = "/api/v1/me/sessions"


@pytest.mark.asyncio
async def test_user_can_list_current_session(
    client: httpx.AsyncClient,
    verified_user_credentials: UserCredentials,
) -> None:
    """Assert owned session metadata identifies the current browser session."""
    await login_headers(client, verified_user_credentials)

    response = await client.get(SESSIONS_PATH)

    assert response.status_code == status.HTTP_200_OK
    assert response.json()["offset"] == 0
    assert response.json()["limit"] == 50
    assert response.json()["total"] == 1
    session = response.json()["items"][0]
    assert session["current"] is True
    assert session["active"] is True
    assert parse_browser_session_id(session["id"]).version == UUID4_VERSION
    assert {
        "session_id",
        "public_id",
        "user_id",
        "csrf",
        "ip_hash",
        "user_agent_hash",
    }.isdisjoint(session)


@pytest.mark.asyncio
@pytest.mark.negative
async def test_expired_unrevoked_session_is_reported_inactive(
    app: FastAPI,
    client: httpx.AsyncClient,
    browser_client_factory: BrowserClientFactory,
    verified_user_credentials: UserCredentials,
) -> None:
    """Report expiry consistently when inactive sessions are requested."""
    await login_headers(client, verified_user_credentials)
    async with browser_client_factory() as second_browser:
        await login_headers(second_browser, verified_user_credentials)
        second_sessions = (await second_browser.get(SESSIONS_PATH)).json()["items"]
        expired_session_id = next(
            session["id"] for session in second_sessions if session["current"]
        )

    async with app.state.core_session_factory() as db_session:
        await db_session.execute(
            update(BrowserSessionDB)
            .where(
                BrowserSessionDB.public_id
                == parse_browser_session_id(expired_session_id)
            )
            .values(expires_at=datetime.now(UTC) - timedelta(minutes=1))
        )
        await db_session.commit()

    response = await client.get(SESSIONS_PATH, params={"active_only": False})

    assert response.status_code == status.HTTP_200_OK
    expired_session = next(
        session
        for session in response.json()["items"]
        if session["id"] == expired_session_id
    )
    assert expired_session["active"] is False
    assert expired_session["revoked_at"] is None


@pytest.mark.asyncio
async def test_user_can_page_through_browser_sessions_with_tied_activity(
    app: FastAPI,
    client: httpx.AsyncClient,
    browser_client_factory: BrowserClientFactory,
    verified_user_credentials: UserCredentials,
) -> None:
    """Page retained sessions in a stable order and count the selected state."""
    await login_headers(client, verified_user_credentials)
    async with browser_client_factory() as second_browser:
        await login_headers(second_browser, verified_user_credentials)
    async with browser_client_factory() as third_browser:
        await login_headers(third_browser, verified_user_credentials)

    sessions = (await client.get(SESSIONS_PATH)).json()["items"]
    session_ids = [session["id"] for session in sessions]
    expired_id = next(session["id"] for session in sessions if not session["current"])
    same_activity = datetime.now(UTC)
    async with app.state.core_session_factory() as db_session:
        await db_session.execute(
            update(BrowserSessionDB)
            .where(
                BrowserSessionDB.public_id.in_(
                    [parse_browser_session_id(session_id) for session_id in session_ids]
                )
            )
            .values(last_seen_at=same_activity)
        )
        await db_session.execute(
            update(BrowserSessionDB)
            .where(BrowserSessionDB.public_id == parse_browser_session_id(expired_id))
            .values(expires_at=same_activity - timedelta(minutes=1))
        )
        await db_session.commit()

    first = await client.get(
        SESSIONS_PATH, params={"active_only": False, "offset": 0, "limit": 2}
    )
    second = await client.get(
        SESSIONS_PATH, params={"active_only": False, "offset": 2, "limit": 2}
    )
    active = await client.get(SESSIONS_PATH, params={"limit": 2})

    assert first.status_code == second.status_code == active.status_code == 200
    assert first.json()["total"] == second.json()["total"] == 3
    assert first.json()["offset"] == 0
    assert second.json()["offset"] == 2
    assert first.json()["limit"] == second.json()["limit"] == 2
    all_ids = [item["id"] for page in (first, second) for item in page.json()["items"]]
    assert all_ids == sorted(session_ids, reverse=True)
    assert len(set(all_ids)) == 3
    assert active.json()["total"] == 2
    assert expired_id not in {item["id"] for item in active.json()["items"]}


@pytest.mark.asyncio
@pytest.mark.system
async def test_user_can_revoke_an_owned_session(
    client: httpx.AsyncClient,
    browser_client_factory: BrowserClientFactory,
    verified_user_credentials: UserCredentials,
) -> None:
    """Assert one browser can revoke another session owned by the same user."""
    await login_headers(client, verified_user_credentials)
    first_session = (await client.get(SESSIONS_PATH)).json()["items"][0]

    async with browser_client_factory() as second_browser:
        headers = await login_headers(second_browser, verified_user_credentials)
        revoke_response = await second_browser.delete(
            f"{SESSIONS_PATH}/{first_session['id']}",
            headers=headers,
        )
        list_response = await second_browser.get(
            SESSIONS_PATH,
            params={"active_only": False},
        )

    assert revoke_response.status_code == status.HTTP_204_NO_CONTENT
    assert revoke_response.content == b""
    revoked = next(
        session
        for session in list_response.json()["items"]
        if session["id"] == first_session["id"]
    )
    assert revoked["active"] is False
    assert revoked["revoked_reason"] == "user_revoked"
    assert (await client.get(SESSIONS_PATH)).status_code == status.HTTP_401_UNAUTHORIZED


@pytest.mark.asyncio
@pytest.mark.negative
async def test_current_session_must_be_ended_through_logout(
    client: httpx.AsyncClient,
    verified_user_credentials: UserCredentials,
) -> None:
    """Keep current-session revocation on the cookie-clearing logout route."""
    headers = await login_headers(client, verified_user_credentials)
    current_session = (await client.get(SESSIONS_PATH)).json()["items"][0]

    response = await client.delete(
        f"{SESSIONS_PATH}/{current_session['id']}",
        headers=headers,
    )
    still_authenticated = await client.get(SESSIONS_PATH)

    assert response.status_code == status.HTTP_409_CONFLICT
    assert response.json()["code"] == "CURRENT_SESSION_REQUIRES_LOGOUT"
    assert still_authenticated.status_code == status.HTTP_200_OK
    assert still_authenticated.json()["items"][0]["current"] is True


@pytest.mark.asyncio
@pytest.mark.negative
async def test_revoke_unknown_owned_session_returns_not_found(
    client: httpx.AsyncClient,
    verified_user_credentials: UserCredentials,
) -> None:
    """Assert session identifiers do not expose sessions the user cannot own."""
    headers = await login_headers(client, verified_user_credentials)

    response = await client.delete(
        f"{SESSIONS_PATH}/00000000-0000-4000-8000-000000000000",
        headers=headers,
    )

    assert response.status_code == status.HTTP_404_NOT_FOUND
    assert response.json()["code"] == "BROWSER_SESSION_NOT_FOUND"


@pytest.mark.asyncio
@pytest.mark.negative
async def test_revoke_session_rejects_unformatted_integer_identifier(
    client: httpx.AsyncClient,
    verified_user_credentials: UserCredentials,
) -> None:
    """Assert raw database-compatible integers are not accepted by the API."""
    headers = await login_headers(client, verified_user_credentials)

    response = await client.delete(f"{SESSIONS_PATH}/1", headers=headers)

    assert response.status_code == status.HTTP_422_UNPROCESSABLE_CONTENT


@pytest.mark.asyncio
@pytest.mark.negative
async def test_session_list_requires_browser_authentication(
    client: httpx.AsyncClient,
) -> None:
    """Assert anonymous callers cannot enumerate browser sessions."""
    response = await client.get(SESSIONS_PATH)

    assert response.status_code == status.HTTP_401_UNAUTHORIZED


@pytest.mark.asyncio
@pytest.mark.negative
async def test_session_list_rejects_oauth2_bearer_without_browser_session(
    app: FastAPI,
    client: httpx.AsyncClient,
    verified_user_credentials: UserCredentials,
) -> None:
    """Assert browser-session management does not accept OAuth2 bearer auth."""
    token_response = await issue_user_token(app, client, verified_user_credentials)
    assert token_response.status_code == status.HTTP_200_OK
    client.cookies.clear()

    response = await client.get(
        SESSIONS_PATH,
        headers={"Authorization": f"Bearer {token_response.json()['access_token']}"},
    )

    assert response.status_code == status.HTTP_401_UNAUTHORIZED
