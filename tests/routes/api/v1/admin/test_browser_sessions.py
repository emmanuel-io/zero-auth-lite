"""Black-box tests for operator browser-session cleanup."""

from datetime import datetime, timedelta, UTC

import httpx
import pytest
from app.db.models.browser_session import BrowserSessionDB
from app.db.models.user import UserDB
from fastapi import FastAPI, status
from sqlalchemy import select

from tests.fixtures.auth import current_user_id_for_email, UserCredentials
from tests.routes.api.helpers import commit_failure_client, login_headers


pytestmark = pytest.mark.api

SESSIONS_PATH = "/api/v1/admin/sessions"


async def add_expired_session(app: FastAPI, user_email: str) -> None:
    """Persist an expired browser session for cleanup."""
    async with app.state.core_session_factory() as db_session:
        user_id = await db_session.scalar(
            select(UserDB.id).where(UserDB.id == current_user_id_for_email(user_email))
        )
        assert user_id is not None
        now = datetime.now(UTC)
        db_session.add(
            BrowserSessionDB(
                id="expired-session-for-cleanup",
                user_id=user_id,
                csrf="expired-csrf-token",
                absolute_expires_at=now + timedelta(hours=8),
                expires_at=now - timedelta(seconds=1),
                last_seen_at=now,
            )
        )
        await db_session.commit()


@pytest.mark.asyncio
async def test_operator_can_delete_expired_sessions(
    app: FastAPI,
    client: httpx.AsyncClient,
    verified_user_credentials: UserCredentials,
) -> None:
    """Assert expired cleanup preserves the operator's active session."""
    headers = await login_headers(client, verified_user_credentials)
    await add_expired_session(app, verified_user_credentials.email)

    response = await client.delete(
        SESSIONS_PATH,
        params={"status": "expired"},
        headers=headers,
    )

    assert response.status_code == status.HTTP_200_OK
    assert response.json() == 1
    assert (await client.get("/api/v1/me")).status_code == status.HTTP_200_OK


@pytest.mark.asyncio
async def test_operator_can_delete_all_sessions(
    client: httpx.AsyncClient,
    verified_user_credentials: UserCredentials,
) -> None:
    """Assert global deletion revokes the operator's own browser session."""
    headers = await login_headers(client, verified_user_credentials)

    response = await client.delete(
        SESSIONS_PATH,
        params={"status": "all"},
        headers=headers,
    )

    assert response.status_code == status.HTTP_200_OK
    assert response.json() == 1
    assert any(
        cookie.startswith("sessionid=") and "Max-Age=0" in cookie
        for cookie in response.headers.get_list("set-cookie")
    )
    assert (await client.get("/api/v1/me")).status_code == status.HTTP_401_UNAUTHORIZED


@pytest.mark.asyncio
@pytest.mark.negative
async def test_global_session_deletion_commit_failure_keeps_operator_authority(
    app: FastAPI,
    client: httpx.AsyncClient,
    verified_user_credentials: UserCredentials,
) -> None:
    """Do not clear operator transport when global deletion rolls back."""
    headers = await login_headers(client, verified_user_credentials)
    session_cookie_name = app.state.settings.session.cookie_name

    async with commit_failure_client(app, client) as failing_client:
        response = await failing_client.delete(
            SESSIONS_PATH,
            params={"status": "all"},
            headers=headers,
        )

        assert failing_client.cookies.get(session_cookie_name) is not None

    async with app.state.core_session_factory() as db_session:
        session_count = len((await db_session.scalars(select(BrowserSessionDB))).all())

    assert response.status_code == status.HTTP_500_INTERNAL_SERVER_ERROR
    assert response.headers.get_list("set-cookie") == []
    assert session_count == 1


@pytest.mark.asyncio
async def test_session_cleanup_requires_valid_status(
    client: httpx.AsyncClient,
    verified_user_credentials: UserCredentials,
) -> None:
    """Assert the cleanup subset remains a typed query contract."""
    headers = await login_headers(client, verified_user_credentials)

    response = await client.delete(
        SESSIONS_PATH,
        params={"status": "inactive"},
        headers=headers,
    )

    assert response.status_code == status.HTTP_422_UNPROCESSABLE_CONTENT
