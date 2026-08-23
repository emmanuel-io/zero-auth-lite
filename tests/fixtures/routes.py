"""Route-level black-box HTTP test fixtures."""

import shutil
from collections.abc import AsyncIterator, Callable
from contextlib import AbstractAsyncContextManager, asynccontextmanager
from datetime import datetime, UTC
from pathlib import Path

import httpx
import pytest
import pytest_asyncio
from alembic import command
from alembic.config import Config
from app.db.models.organization import OrganizationDB
from app.db.models.organization_membership import OrganizationMembershipDB
from app.db.models.user import UserDB, UserEmailDB
from app.identity.users.enums import OrganizationUserRole, UserEmailStatus
from app.main import create_app
from app.oauth2.oidc.keys import get_signing_key, get_verify_key
from app.settings.root import Settings
from asgi_lifespan import LifespanManager
from fastapi import FastAPI
from pydantic import BaseModel
from sqlalchemy import insert

from tests.fixtures.app import _raw_oauth2_key_pair_b64, _with_model_updates
from tests.fixtures.auth import UserCredentials


PROJECT_ROOT = Path(__file__).parents[2]
BrowserClientFactory = Callable[
    [],
    AbstractAsyncContextManager[httpx.AsyncClient],
]
"""Factory that opens a fresh cookie-isolated browser client."""


@pytest.fixture(scope="session")
def migrated_database_template(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """Create one migrated SQLite database to copy for each route test."""
    template_directory = tmp_path_factory.mktemp("route-database-template")
    template_path = template_directory / "zero_auth.db"
    alembic_config = Config(str(PROJECT_ROOT / "alembic.ini"))
    alembic_config.set_main_option(
        "script_location",
        str(PROJECT_ROOT / "alembic"),
    )

    with pytest.MonkeyPatch.context() as monkeypatch:
        monkeypatch.setenv(
            "ZA_DB_PATH",
            str(template_path),
        )
        command.upgrade(alembic_config, "head")

    return template_path


def _configure_test_environment(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """Set the isolated environment used by route-level HTTP tests."""
    prv_key_b64, pub_key_b64 = _raw_oauth2_key_pair_b64()
    monkeypatch.setenv(
        "ZA_DB_PATH",
        str(tmp_path / "zero_auth.db"),
    )
    monkeypatch.setenv("ZA_RUNTIME_DIR", str(tmp_path))
    monkeypatch.setenv("ZA_OAUTH2__PRV_KEY_B64", prv_key_b64)
    monkeypatch.setenv("ZA_OAUTH2__PUB_KEY_B64", pub_key_b64)
    monkeypatch.setenv("ZA_OAUTH2__JWT_ISSUER", "https://issuer.test")
    monkeypatch.setenv("ZA_OAUTH2__JWT_AUDIENCE", "test-zero-auth-lite-api")
    monkeypatch.setenv("ZA_OAUTH2__JWT_KEY_ID", "test-key")
    monkeypatch.setenv("ZA_OAUTH2__JWKS_ENABLED", "true")
    monkeypatch.setenv("ZA_OAUTH2__OIDC_ENABLED", "true")
    monkeypatch.setenv("ZA_OAUTH2__ALLOW_CLIENT_SECRET_POST", "false")
    monkeypatch.setenv("ZA_OAUTH2__AUTHORIZATION_CODE_ENABLED", "true")
    monkeypatch.setenv("ZA_OAUTH2__REFRESH_TOKEN_ENABLED", "true")
    monkeypatch.setenv("ZA_OAUTH2__CLIENT_CREDENTIALS_ENABLED", "true")
    monkeypatch.setenv("ZA_OAUTH2__DEVICE_CODE_ENABLED", "true")
    monkeypatch.setenv(
        "ZA_OAUTH2__AUTHORIZATION_CODE_HASH_SECRET",
        "test-authorization-code-hash-secret-with-more-than-32-bytes",
    )
    monkeypatch.setenv(
        "ZA_OAUTH2__TOKEN_HASH_SECRET",
        "test-oauth2-token-hash-secret-with-more-than-32-bytes",
    )
    monkeypatch.setenv("ZA_SESSION__COOKIE_DOMAIN", "")
    monkeypatch.setenv("ZA_SESSION__COOKIE_SECURE", "false")
    monkeypatch.setenv(
        "ZA_SESSION__ID_HASH_SECRET",
        "test-session-id-hash-secret-with-more-than-32-bytes",
    )
    monkeypatch.setenv("ZA_SESSION__CSRF__COOKIE_DOMAIN", "")
    monkeypatch.setenv("ZA_SESSION__CSRF__COOKIE_SECURE", "false")
    monkeypatch.setenv("ZA_MAIL__ENABLED", "false")
    monkeypatch.setenv("ZA_UI__AUTHENTICATION", "external")
    monkeypatch.setenv(
        "ZA_UI__EXTERNAL_LOGIN_URL",
        "https://frontend.test/login",
    )
    monkeypatch.delenv("ZA_DEFAULT_REDIRECT_URL", raising=False)
    monkeypatch.delenv("ZA_BOOTSTRAP__OPERATOR_EMAIL", raising=False)
    monkeypatch.delenv("ZA_BOOTSTRAP__OPERATOR_PASSWORD", raising=False)


def _build_test_settings(settings_overrides: dict[str, object]) -> Settings:
    """Return canonical test settings with explicit nested overrides."""
    settings = Settings()
    if settings_overrides:
        section_updates = {
            section_name: (
                _with_model_updates(current_value, values)
                if isinstance(
                    current_value := getattr(settings, section_name), BaseModel
                )
                and isinstance(values, dict)
                else values
            )
            for section_name, values in settings_overrides.items()
        }
        settings = Settings.model_validate(
            {
                **settings.model_dump(),
                **section_updates,
            }
        )
    return settings


@pytest.fixture
def settings_overrides(request: pytest.FixtureRequest) -> dict[str, object]:
    """Return explicit setting overrides supplied through ``app_settings``."""
    return getattr(request, "param", {})


@pytest_asyncio.fixture
async def app(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    settings_overrides: dict[str, object],
    migrated_database_template: Path,
) -> AsyncIterator[FastAPI]:
    """Create the canonical app and enter the real FastAPI lifespan."""
    shutil.copyfile(migrated_database_template, tmp_path / "zero_auth.db")
    _configure_test_environment(monkeypatch, tmp_path)
    get_signing_key.cache_clear()
    get_verify_key.cache_clear()
    settings = _build_test_settings(settings_overrides)
    test_app = create_app(settings)
    try:
        async with LifespanManager(test_app):
            yield test_app
    finally:
        get_signing_key.cache_clear()
        get_verify_key.cache_clear()


@pytest_asyncio.fixture
async def client(app: FastAPI) -> AsyncIterator[httpx.AsyncClient]:
    """Create a cookie-preserving HTTPX client bound to the ASGI app."""
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(
        transport=transport,
        base_url="http://testserver",
    ) as async_client:
        yield async_client


@pytest.fixture
def browser_client_factory(app: FastAPI) -> BrowserClientFactory:
    """Return a factory for independent browser clients."""

    @asynccontextmanager
    async def create_client() -> AsyncIterator[httpx.AsyncClient]:
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(
            transport=transport,
            base_url="http://testserver",
        ) as async_client:
            yield async_client

    return create_client


@pytest_asyncio.fixture
async def verified_user_credentials(app: FastAPI) -> UserCredentials:
    """Create a verified active user and return its login credentials."""
    credentials = UserCredentials(
        email="admin@example.com",
        password="S3cretPass1",  # noqa: S106
    )

    async with app.state.core_session_factory() as session:
        organization = (
            await session.execute(
                insert(OrganizationDB)
                .values(name="Test Organization")
                .returning(OrganizationDB)
            )
        ).scalar_one()
        user = UserDB(
            first_name="Admin",
            last_name="User",
            hashed_password=app.state.password_hasher.hash(credentials.password),
            is_active=True,
            is_operator=True,
        )
        session.add(user)
        await session.flush()
        session.add(
            UserEmailDB(
                user_id=user.id,
                email=credentials.email,
                normalized_email=credentials.email,
                status=UserEmailStatus.CURRENT,
                verified_at=datetime.now(UTC),
            )
        )
        session.add(
            OrganizationMembershipDB(
                user_id=user.id,
                organization_id=organization.id,
                role=OrganizationUserRole.ADMIN,
            )
        )
        await session.commit()

    return credentials
