"""Verify credential preparation releases incidental browser-session writes."""

from datetime import datetime, timedelta, UTC

import httpx
import pytest
from app.db.models.browser_session import BrowserSessionDB
from app.db.models.organization import OrganizationDB
from app.password.async_hashing import hash_password
from app.password.protocols import PasswordHasherProtocol
from fastapi import FastAPI, status
from sqlalchemy import update

from app.identity.services import lifecycle
from app.oauth2.clients.management import registration
from tests.fixtures.auth import UserCredentials
from tests.routes.api.helpers import login_headers


pytestmark = pytest.mark.api


@pytest.mark.asyncio
@pytest.mark.parametrize("surface", ["server/users", "organization/users", "clients"])
async def test_creation_releases_sqlite_writer_before_hashing(
    app: FastAPI,
    client: httpx.AsyncClient,
    verified_user_credentials: UserCredentials,
    monkeypatch: pytest.MonkeyPatch,
    surface: str,
) -> None:
    """Allow another writer to commit while an admin prepares credentials."""
    headers = await login_headers(client, verified_user_credentials)
    organization = await client.post(
        "/api/v1/server/organizations", json={"name": "Hashing"}, headers=headers
    )
    assert organization.status_code == status.HTTP_201_CREATED
    organization_id = organization.json()["id"]
    stale_activity = datetime.now(UTC) - timedelta(
        seconds=app.state.settings.browser_session.slide_seconds + 1
    )
    async with app.state.core_session_factory.begin() as session:
        await session.execute(
            update(BrowserSessionDB).values(last_seen_at=stale_activity)
        )

    hashing_ran = False

    async def hash_with_concurrent_writer(
        password_hasher: PasswordHasherProtocol, password: str
    ) -> str:
        nonlocal hashing_ran
        async with app.state.core_session_factory.begin() as session:
            await session.execute(update(OrganizationDB).values(name="Concurrent"))
        hashing_ran = True
        return await hash_password(password_hasher, password)

    monkeypatch.setattr(lifecycle, "hash_password", hash_with_concurrent_writer)
    monkeypatch.setattr(registration, "hash_password", hash_with_concurrent_writer)
    if surface == "clients":
        path = "/api/v1/server/oauth2/clients"
        payload = {
            "name": "Hashing Client",
            "grant_types": ["client_credentials"],
            "scopes": ["read"],
            "is_confidential": True,
        }
    else:
        path = f"/api/v1/{surface}"
        payload = {"email": "hashing@example.com"}
        if surface == "server/users":
            payload["organization_id"] = organization_id
        else:
            payload["password"] = "M3mberSecret1!"  # noqa: S105

    response = await client.post(path, json=payload, headers=headers)

    assert response.status_code == status.HTTP_201_CREATED
    assert hashing_ran
