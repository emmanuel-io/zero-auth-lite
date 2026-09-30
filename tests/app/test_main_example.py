"""Smoke tests for the canonical Zero Auth Lite application."""

from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from app.main import create_app
from app.settings.root import Settings
from app.settings.ui import (
    IdentityWorkflowUIMode,
    ManagementAuthenticationMode,
    UISettings,
)
from asgi_lifespan import LifespanManager
from fastapi import FastAPI, status
from httpx import ASGITransport, AsyncClient


pytestmark = pytest.mark.integration
PROJECT_ROOT = Path(__file__).parents[2]
EXTERNAL_LOGIN_URL = "https://frontend.test/login"


@pytest.fixture
def local_example_app(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> FastAPI:
    """Create the app with local settings and an Alembic-migrated database."""
    monkeypatch.setenv(
        "ZA_DB_PATH",
        str(tmp_path / "zero_auth.db"),
    )
    monkeypatch.setenv("ZA_RUNTIME_DIR", str(tmp_path))
    alembic_config = Config(str(PROJECT_ROOT / "alembic.ini"))
    alembic_config.set_main_option(
        "script_location",
        str(PROJECT_ROOT / "alembic"),
    )
    command.upgrade(alembic_config, "head")

    return create_app(
        Settings(
            ui=UISettings(
                identity_workflow_mode=IdentityWorkflowUIMode.EXTERNAL,
                management_authentication=ManagementAuthenticationMode.EXTERNAL,
                urls={
                    "login": EXTERNAL_LOGIN_URL,
                    "logout": "https://frontend.test/logout",
                },
            ),
        )
    )


def test_full_server_example_imports_and_registers_auth_routes() -> None:
    """Assert the app creates an auth-focused FastAPI app."""
    app = create_app(
        Settings(
            ui=UISettings(
                identity_workflow_mode=IdentityWorkflowUIMode.EXTERNAL,
                management_authentication=ManagementAuthenticationMode.EXTERNAL,
                urls={
                    "login": EXTERNAL_LOGIN_URL,
                    "logout": "https://frontend.test/logout",
                },
            ),
        )
    )

    assert isinstance(app, FastAPI)
    paths = set(app.openapi()["paths"])
    assert "/health/live" in paths
    assert "/health/ready" in paths
    assert "/health" not in paths
    assert "/api/v1/sessions/login" in paths
    assert "/api/v1/auth/register" in paths
    assert "/api/v1/me/sessions" in paths
    assert "/api/v1/me" in paths
    assert "/api/v1/server/organizations" in paths
    assert "/api/v1/server/users" in paths
    assert "/api/v1/server/oauth2/clients" in paths
    assert "/oauth2/token" in paths
    assert "/.well-known/oauth-authorization-server" in paths
    assert "/.well-known/openid-configuration" in paths
    assert "/oauth2/jwks.json" in paths


@pytest.mark.asyncio
async def test_full_server_example_lifespan_starts(local_example_app: FastAPI) -> None:
    """Assert the documented app can enter FastAPI lifespan."""
    async with LifespanManager(local_example_app):
        assert hasattr(local_example_app.state, "core_engine")


@pytest.mark.asyncio
async def test_full_server_example_auth_dependencies_return_auth_errors(
    local_example_app: FastAPI,
) -> None:
    """Assert protected protocol routes use app auth dependencies, not placeholders."""
    async with (
        LifespanManager(local_example_app),
        AsyncClient(
            transport=ASGITransport(
                app=local_example_app,
                raise_app_exceptions=False,
            ),
            base_url="http://testserver",
        ) as client,
    ):
        userinfo = await client.get("/oauth2/userinfo")
        device_verify = await client.post(
            "/oauth2/device/verify", data={"user_code": "ABCD-EFGH"}
        )
        sessions = await client.get("/api/v1/me/sessions")

    assert userinfo.status_code == status.HTTP_401_UNAUTHORIZED
    assert device_verify.status_code == status.HTTP_401_UNAUTHORIZED
    assert sessions.status_code == status.HTTP_401_UNAUTHORIZED
