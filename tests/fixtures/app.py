"""Shared application fixtures for tests."""
# ruff: noqa: PLC0415

import base64
import os
from collections.abc import AsyncIterator
from datetime import datetime, UTC
from pathlib import Path

import httpx
import pytest
import pytest_asyncio
from app.db.models.oauth2_client import OAuth2ClientDB
from app.db.models.organization import OrganizationDB
from app.db.models.organization_membership import OrganizationMembershipDB
from app.db.models.user import UserDB, UserEmailDB
from app.identity.users.enums import OrganizationUserRole, UserEmailStatus
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from fastapi import FastAPI
from pydantic import BaseModel
from sqlalchemy import insert
from sqlalchemy.ext.asyncio import AsyncSession

from tests.fixtures.auth import UserCredentials


os.environ.setdefault(
    "ZA_SESSION__ID_HASH_SECRET",
    "test-session-id-hash-secret-with-more-than-32-bytes",
)
os.environ.setdefault(
    "ZA_OAUTH2__AUTHORIZATION_CODE_HASH_SECRET",
    "test-authorization-code-hash-secret-with-more-than-32-bytes",
)


def _with_model_updates(model: BaseModel, updates: dict[str, object]) -> BaseModel:
    """Return a validated immutable model with recursive section updates."""
    values = model.model_dump()
    for field_name, value in updates.items():
        current_value = getattr(model, field_name)
        updated_value = value
        if isinstance(current_value, BaseModel) and isinstance(value, dict):
            updated_value = _with_model_updates(current_value, value)
        values[field_name] = updated_value
    return type(model).model_validate(values)


def _raw_oauth2_key_pair_b64() -> tuple[str, str]:
    """Return a generated raw Ed25519 private/public key pair as base64 text."""
    private_key = ed25519.Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    private_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return (
        base64.b64encode(private_bytes).decode(),
        base64.b64encode(public_bytes).decode(),
    )


@pytest_asyncio.fixture
async def app(  # noqa: PLR0915
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    settings_overrides: dict[str, object],
) -> AsyncIterator[FastAPI]:
    """Create a FastAPI app with isolated test settings."""
    prv_key_b64, pub_key_b64 = _raw_oauth2_key_pair_b64()
    monkeypatch.setenv(
        "ZA_DB_PATH",
        str(tmp_path / "zero_auth.db"),
    )
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
    monkeypatch.delenv("ZA_BOOTSTRAP__OPERATOR_EMAIL", raising=False)
    monkeypatch.delenv("ZA_BOOTSTRAP__OPERATOR_PASSWORD", raising=False)
    from app.db.base import Base
    from app.db.engine import create_engine, create_session_factory
    from app.db.models.auth_event import AuthEventOutboxDB
    from app.db.models.auth_token import UserAuthTokenDB
    from app.db.models.browser_session import BrowserSessionDB
    from app.db.models.oauth2_authorization_code import (
        OAuth2AuthorizationCodeDB,
    )
    from app.db.models.oauth2_authorization_transaction import (
        OAuth2AuthorizationTransactionDB,
    )
    from app.db.models.oauth2_client import (
        OAuth2ClientDB,
        OAuth2ClientMachineOrganizationDB,
        OAuth2ClientUserOrganizationDB,
    )
    from app.db.models.oauth2_device_authorization import (
        OAuth2DeviceAuthorizationDB,
    )
    from app.db.models.oauth2_session import OAuth2SessionDB
    from app.db.models.oauth2_token_pair import (
        OAuth2RefreshTokenHistoryDB,
        OAuth2TokenPairDB,
    )
    from app.db.models.organization import OrganizationDB
    from app.db.models.organization_membership import OrganizationMembershipDB
    from app.db.models.user import UserDB, UserEmailDB
    from app.db.snowflake import (
        acquire_snowflake_node_lease,
        configure_snowflake_generator,
        unconfigure_snowflake_generator,
    )
    from app.main import create_app
    from app.oauth2.oidc.keys import (
        get_signing_key,
        get_verify_key,
    )
    from app.settings.root import Settings

    get_signing_key.cache_clear()
    get_verify_key.cache_clear()
    settings = Settings()
    if settings_overrides:
        section_updates = {
            section_name: (
                _with_model_updates(getattr(settings, section_name), values)
                if isinstance(getattr(settings, section_name), BaseModel)
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
    test_app = create_app(settings)
    test_app.state.core_engine = create_engine(
        settings.db_path,
        echo=settings.db_echo,
    )
    test_app.state.core_session_factory = create_session_factory(
        test_app.state.core_engine
    )
    snowflake_lease = acquire_snowflake_node_lease(
        lock_directory=tmp_path / "snowflake",
        requested_node_id=None,
    )
    configure_snowflake_generator(snowflake_lease.node_id)
    try:
        async with test_app.state.core_engine.begin() as conn:
            await conn.run_sync(
                Base.metadata.create_all,
                tables=[
                    OrganizationDB.__table__,
                    UserDB.__table__,
                    OrganizationMembershipDB.__table__,
                    UserEmailDB.__table__,
                    BrowserSessionDB.__table__,
                    OAuth2ClientDB.__table__,
                    OAuth2ClientUserOrganizationDB.__table__,
                    OAuth2ClientMachineOrganizationDB.__table__,
                    OAuth2AuthorizationCodeDB.__table__,
                    OAuth2AuthorizationTransactionDB.__table__,
                    OAuth2DeviceAuthorizationDB.__table__,
                    OAuth2SessionDB.__table__,
                    OAuth2TokenPairDB.__table__,
                    OAuth2RefreshTokenHistoryDB.__table__,
                    UserAuthTokenDB.__table__,
                    AuthEventOutboxDB.__table__,
                ],
            )
        yield test_app
    finally:
        await test_app.state.core_engine.dispose()
        unconfigure_snowflake_generator()
        snowflake_lease.release()

    get_signing_key.cache_clear()
    get_verify_key.cache_clear()


@pytest.fixture
def settings_overrides(request: pytest.FixtureRequest) -> dict[str, object]:
    """Return explicit setting overrides supplied through ``app_settings``."""
    return getattr(request, "param", {})


@pytest_asyncio.fixture
async def client(app: FastAPI) -> AsyncIterator[httpx.AsyncClient]:
    """Create an async HTTP client bound to the ASGI app."""
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(
        transport=transport,
        base_url="http://testserver",
    ) as async_client:
        yield async_client


@pytest_asyncio.fixture
async def db_session(app: FastAPI) -> AsyncIterator[AsyncSession]:
    """Open an isolated SQLAlchemy session against the test database."""
    async with app.state.core_session_factory() as session:
        yield session


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
        user = (
            await session.execute(
                insert(UserDB)
                .values(
                    first_name="Admin",
                    last_name="User",
                    hashed_password=app.state.password_hasher.hash(
                        credentials.password
                    ),
                    is_active=True,
                    is_operator=True,
                )
                .returning(UserDB)
            )
        ).scalar_one()
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
        session.add(
            OAuth2ClientDB(
                client_id="test-user-client",
                client_secret=None,
                name="Test User Client",
                grant_types=["authorization_code", "refresh_token"],
                scopes=["read"],
                redirect_uris=["https://test-client.example/callback"],
                is_confidential=False,
                requires_consent=True,
                is_active=True,
            )
        )
        await session.commit()

    return credentials
