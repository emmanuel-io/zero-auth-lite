"""Black-box HTTP tests for the health endpoint."""

import httpx
import pytest
from fastapi import FastAPI, status


pytestmark = pytest.mark.api


@pytest.mark.asyncio
async def test_health_returns_ok_while_lifespan_is_active(
    app: FastAPI,
    client: httpx.AsyncClient,
) -> None:
    """Assert the canonical app answers health checks over real HTTP."""
    assert hasattr(app.state, "core_engine")

    response = await client.get("/health")

    assert response.status_code == status.HTTP_200_OK
    assert response.headers["content-type"].startswith("application/json")
    assert response.json() == {"status": "ok"}
