"""Shared HTTP helpers for versioned API route tests."""

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

import httpx
from app.db.dependencies import get_db_session
from fastapi import FastAPI, status
from sqlalchemy.ext.asyncio import AsyncSession

from tests.fixtures.auth import login_browser, UserCredentials


TEST_ORIGIN = "http://testserver"


def _raise_commit_failure() -> None:
    """Raise the synthetic failure used after a route finishes."""
    msg = "forced request commit failure"
    raise RuntimeError(msg)


@asynccontextmanager
async def commit_failure_client(
    app: FastAPI, source_client: httpx.AsyncClient
) -> AsyncIterator[httpx.AsyncClient]:
    """Return a cookie-preserving client whose request transaction cannot commit."""

    async def fail_after_route() -> AsyncIterator[AsyncSession]:
        async with app.state.core_session_factory() as session:
            try:
                yield session
                _raise_commit_failure()
            except Exception:
                await session.rollback()
                raise

    app.dependency_overrides[get_db_session] = fail_after_route
    transport = httpx.ASGITransport(app=app, raise_app_exceptions=False)
    try:
        async with httpx.AsyncClient(
            transport=transport,
            base_url=source_client.base_url,
            cookies=source_client.cookies,
        ) as failing_client:
            yield failing_client
    finally:
        app.dependency_overrides.pop(get_db_session, None)


async def login_headers(
    client: httpx.AsyncClient,
    credentials: UserCredentials,
) -> dict[str, str]:
    """Log in a browser user and return headers for CSRF-protected writes."""
    response = await login_browser(client, credentials)
    assert response.status_code == status.HTTP_204_NO_CONTENT
    csrf_header = next(
        name for name in response.headers if name.lower().startswith("x-csrf")
    )
    return {
        "Origin": TEST_ORIGIN,
        csrf_header: response.headers[csrf_header],
    }
