"""Black-box HTTP tests for the health endpoint."""

from unittest.mock import patch

import httpx
import pytest
from app.health import router as health_router_module
from fastapi import FastAPI, status
from sqlalchemy.exc import OperationalError


pytestmark = pytest.mark.api


@pytest.mark.asyncio
async def test_liveness_returns_ok_while_lifespan_is_active(
    app: FastAPI,
    client: httpx.AsyncClient,
) -> None:
    """Assert liveness does not depend on the state of SQLite."""
    assert hasattr(app.state, "core_engine")

    response = await client.get("/health/live")

    assert response.status_code == status.HTTP_200_OK
    assert response.headers["content-type"].startswith("application/json")
    assert response.json() == {"status": "ok"}


@pytest.mark.asyncio
async def test_readiness_returns_ok_for_current_migrated_database(
    client: httpx.AsyncClient,
) -> None:
    """Assert readiness confirms SQLite and the checkout's Alembic heads."""
    response = await client.get("/health/ready")

    assert response.status_code == status.HTTP_200_OK
    assert response.json() == {"status": "ok"}


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "failure",
    [
        OperationalError("SELECT version_num", {}, OSError("database unavailable")),
        RuntimeError("Database schema is out of date"),
    ],
    ids=["sqlite-unavailable", "migration-out-of-date"],
)
async def test_readiness_fails_closed_without_exposing_the_cause(
    client: httpx.AsyncClient,
    monkeypatch: pytest.MonkeyPatch,
    failure: Exception,
) -> None:
    """Return one stable 503 for connection and migration failures."""

    async def fail_readiness(_engine: object) -> None:
        raise failure

    monkeypatch.setattr(
        health_router_module,
        "ensure_database_is_migrated",
        fail_readiness,
    )

    response = await client.get("/health/ready")

    assert response.status_code == status.HTTP_503_SERVICE_UNAVAILABLE
    assert response.json() == {"status": "not_ready"}


@pytest.mark.asyncio
async def test_readiness_logs_only_failure_and_recovery_transitions(
    app: FastAPI,
    client: httpx.AsyncClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Prevent repeated readiness probes from flooding operational logs."""

    async def fail_readiness(_engine: object) -> None:
        message = "Database schema is out of date"
        raise RuntimeError(message)

    async def pass_readiness(_engine: object) -> None:
        return None

    app.state.readiness_failure_active = False
    monkeypatch.setattr(
        health_router_module,
        "ensure_database_is_migrated",
        fail_readiness,
    )
    with (
        patch.object(health_router_module.logger, "warning") as warning,
        patch.object(health_router_module.logger, "info") as info,
    ):
        await client.get("/health/ready")
        await client.get("/health/ready")
        monkeypatch.setattr(
            health_router_module,
            "ensure_database_is_migrated",
            pass_readiness,
        )
        await client.get("/health/ready")

    warning.assert_called_once_with(
        "event=readiness outcome=failure reason=%s",
        "RuntimeError",
    )
    info.assert_called_once_with("event=readiness outcome=recovered")


@pytest.mark.asyncio
async def test_legacy_health_route_is_absent(client: httpx.AsyncClient) -> None:
    """Keep the removed ambiguous health contract out of the public surface."""
    response = await client.get("/health")

    assert response.status_code == status.HTTP_404_NOT_FOUND
