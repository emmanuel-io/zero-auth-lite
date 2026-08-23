"""Black-box HTTP tests for OAuth2 device authorization flow behavior."""

import base64
import json
from datetime import datetime, timedelta, UTC
from typing import cast
from unittest.mock import Mock

import httpx
import pytest
from app.db.errors import DatabaseBusyError
from app.db.models.oauth2_client import OAuth2ClientDB
from app.db.models.oauth2_device_authorization import (
    OAuth2DeviceAuthorizationDB,
)
from app.db.models.user import UserDB, UserEmailDB
from app.identity.users.enums import UserEmailStatus
from app.oauth2.tokens.hash import hash_oauth2_token
from app.password.pwdlib_hasher import PwdlibPasswordHasher
from fastapi import FastAPI, status
from sqlalchemy import func, select, update

from app.oauth2.devices import (
    authorization as authorization_workflow,
    polling as polling_workflow,
)
from tests.fixtures.auth import (
    current_user_id_for_email,
    login_browser,
    UserCredentials,
)
from tests.fixtures.settings import app_settings


pytestmark = pytest.mark.api

DEVICE_GRANT_TYPE = "urn:ietf:params:oauth:grant-type:device_code"
EXPECTED_DEVICE_AUTHORIZATIONS_AFTER_RETRY = 2
EXPECTED_SLOW_DOWN_INTERVAL_SECONDS = 10
TEST_ORIGIN = "http://testserver"
PASSWORD_HASHER = PwdlibPasswordHasher()


def decode_unverified_jwt_payload(token: str) -> dict[str, object]:
    """Decode JWT payload without verifying the signature."""
    _header, payload, _signature = token.split(".")
    padded_payload = payload + "=" * (-len(payload) % 4)
    return cast(
        "dict[str, object]", json.loads(base64.urlsafe_b64decode(padded_payload))
    )


async def create_device_client(
    app: FastAPI,
    *,
    client_id: str = "device-client",
    scopes: list[str] | None = None,
    is_confidential: bool = False,
    is_active: bool = True,
) -> str | None:
    """Create an OAuth2 device client and return its raw secret if confidential."""
    raw_secret = f"{client_id}-secret" if is_confidential else None
    async with app.state.core_session_factory() as db_session:
        db_session.add(
            OAuth2ClientDB(
                client_id=client_id,
                client_secret=PASSWORD_HASHER.hash(raw_secret) if raw_secret else None,
                name="Device Client",
                grant_types=[DEVICE_GRANT_TYPE, "refresh_token"],
                scopes=scopes or ["read"],
                redirect_uris=[],
                is_confidential=is_confidential,
                is_active=is_active,
            )
        )
        await db_session.commit()
    return raw_secret


async def login_browser_session(
    client: httpx.AsyncClient,
    credentials: UserCredentials,
) -> httpx.Response:
    """Log in through browser session auth for device approval tests."""
    return await login_browser(client, credentials)


async def request_device_authorization(
    client: httpx.AsyncClient,
    *,
    client_id: str = "device-client",
    scope: str = "read",
    client_secret: str | None = None,
) -> httpx.Response:
    """Request a device authorization response."""
    data = {
        "client_id": client_id,
        "scope": scope,
    }
    if client_secret is not None:
        data["client_secret"] = client_secret
    return await client.post("/oauth2/device_authorization", data=data)


async def poll_device_code(
    client: httpx.AsyncClient,
    *,
    device_code: str,
    client_id: str = "device-client",
    client_secret: str | None = None,
) -> httpx.Response:
    """Poll the token endpoint for a device-code grant."""
    data = {
        "grant_type": DEVICE_GRANT_TYPE,
        "device_code": device_code,
        "client_id": client_id,
    }
    if client_secret is not None:
        data["client_secret"] = client_secret
    return await client.post("/oauth2/token", data=data)


async def approve_user_code(
    app: FastAPI,
    client: httpx.AsyncClient,
    *,
    user_code: str,
    credentials: UserCredentials,
    include_csrf: bool = True,
) -> httpx.Response:
    """Approve a device user code through the browser endpoint."""
    login_response = await login_browser_session(client, credentials)
    assert login_response.status_code == status.HTTP_204_NO_CONTENT
    headers = {"Origin": TEST_ORIGIN}
    if include_csrf:
        headers[app.state.settings.session.csrf.header_name] = login_response.headers[
            app.state.settings.session.csrf.header_name
        ]
    return await client.post(
        "/oauth2/device/verify",
        data={"user_code": user_code, "decision": "approve"},
        headers=headers,
    )


@pytest.mark.asyncio
async def test_device_authorization_polling_returns_authorization_pending(
    app: FastAPI,
    client: httpx.AsyncClient,
) -> None:
    """Assert device polling waits until a user approves the code."""
    await create_device_client(app)
    authorization_response = await request_device_authorization(client)
    assert authorization_response.status_code == status.HTTP_200_OK

    token_response = await poll_device_code(
        client,
        device_code=authorization_response.json()["device_code"],
    )

    assert token_response.status_code == status.HTTP_400_BAD_REQUEST
    assert token_response.json()["error"] == "authorization_pending"
    async with app.state.core_session_factory() as db_session:
        last_polled_at = await db_session.scalar(
            select(OAuth2DeviceAuthorizationDB.last_polled_at)
        )
    assert last_polled_at is not None


@pytest.mark.asyncio
async def test_device_poll_transaction_failure_replaces_protocol_outcome(
    app: FastAPI,
    client: httpx.AsyncClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Do not report pending when its independent transaction did not commit."""
    await create_device_client(app)
    authorization_response = await request_device_authorization(client)

    async def fail_poll(**_kwargs: object) -> polling_workflow.DevicePollDecision:
        raise DatabaseBusyError

    monkeypatch.setattr(polling_workflow, "evaluate_device_poll", fail_poll)
    response = await poll_device_code(
        client,
        device_code=authorization_response.json()["device_code"],
    )

    assert response.status_code == status.HTTP_503_SERVICE_UNAVAILABLE
    assert response.headers["retry-after"] == "1"
    assert response.json() == {"error": "temporarily_unavailable"}


@pytest.mark.asyncio
async def test_device_authorization_polling_too_fast_returns_slow_down(
    app: FastAPI,
    client: httpx.AsyncClient,
) -> None:
    """Assert device polling enforces the returned interval."""
    await create_device_client(app)
    authorization_response = await request_device_authorization(client)
    assert authorization_response.status_code == status.HTTP_200_OK
    device_code = authorization_response.json()["device_code"]

    first_response = await poll_device_code(client, device_code=device_code)
    second_response = await poll_device_code(client, device_code=device_code)

    assert first_response.status_code == status.HTTP_400_BAD_REQUEST
    assert first_response.json()["error"] == "authorization_pending"
    assert second_response.status_code == status.HTTP_400_BAD_REQUEST
    assert second_response.json()["error"] == "slow_down"
    async with app.state.core_session_factory() as db_session:
        poll_state = (
            await db_session.execute(
                select(
                    OAuth2DeviceAuthorizationDB.last_polled_at,
                    OAuth2DeviceAuthorizationDB.interval_seconds,
                )
            )
        ).one()
    assert poll_state.last_polled_at is not None
    assert poll_state.interval_seconds == EXPECTED_SLOW_DOWN_INTERVAL_SECONDS


@pytest.mark.asyncio
@pytest.mark.system
async def test_device_authorization_approval_issues_token_pair(
    app: FastAPI,
    client: httpx.AsyncClient,
    verified_user_credentials: UserCredentials,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Assert an approved device code can be exchanged for bearer tokens."""
    await create_device_client(app)
    authorization_response = await request_device_authorization(client)
    assert authorization_response.status_code == status.HTTP_200_OK
    device_body = authorization_response.json()

    logger = Mock()
    monkeypatch.setattr(authorization_workflow, "logger", logger)
    approval_response = await approve_user_code(
        app,
        client,
        user_code=device_body["user_code"],
        credentials=verified_user_credentials,
    )
    assert approval_response.status_code == status.HTTP_200_OK
    assert "Approved" in approval_response.text

    token_response = await poll_device_code(
        client,
        device_code=device_body["device_code"],
    )

    assert token_response.status_code == status.HTTP_200_OK
    body = token_response.json()
    assert body["access_token"]
    assert body["refresh_token"]
    claims = decode_unverified_jwt_payload(body["access_token"])
    assert claims["client_id"] == "device-client"
    assert claims["scope"] == "read"
    message = logger.info.call_args.args[0]
    assert "event=oauth2_device_authorization outcome=attempted" in message
    assert "decision=%s" in message
    assert logger.info.call_args.args[1] == "approved"


@pytest.mark.asyncio
@pytest.mark.negative
async def test_device_code_exchange_does_not_mask_internal_value_error(
    app: FastAPI,
    client: httpx.AsyncClient,
    verified_user_credentials: UserCredentials,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Let unexpected issuance defects escape the OAuth2 error mapping."""
    await create_device_client(app)
    authorization_response = await request_device_authorization(client)
    device_body = authorization_response.json()
    approval_response = await approve_user_code(
        app,
        client,
        user_code=device_body["user_code"],
        credentials=verified_user_credentials,
    )
    assert approval_response.status_code == status.HTTP_200_OK

    async def fail_issuance(*_args: object, **_kwargs: object) -> None:
        msg = "unexpected issuance defect"
        raise ValueError(msg)

    monkeypatch.setattr(
        polling_workflow.TokenIssuanceService,
        "issue_new_session",
        fail_issuance,
    )

    with pytest.raises(ValueError, match="unexpected issuance defect"):
        await poll_device_code(client, device_code=device_body["device_code"])


@pytest.mark.asyncio
@pytest.mark.negative
async def test_device_code_rejects_reuse_after_success(
    app: FastAPI,
    client: httpx.AsyncClient,
    verified_user_credentials: UserCredentials,
) -> None:
    """Assert a device code can issue tokens only once."""
    await create_device_client(app)
    authorization_response = await request_device_authorization(client)
    device_body = authorization_response.json()
    await approve_user_code(
        app,
        client,
        user_code=device_body["user_code"],
        credentials=verified_user_credentials,
    )

    first_response = await poll_device_code(
        client,
        device_code=device_body["device_code"],
    )
    second_response = await poll_device_code(
        client,
        device_code=device_body["device_code"],
    )

    assert first_response.status_code == status.HTTP_200_OK
    assert second_response.status_code == status.HTTP_400_BAD_REQUEST
    assert second_response.json()["error"] == "invalid_grant"


@pytest.mark.asyncio
@pytest.mark.negative
async def test_device_code_rejects_expired_code(
    app: FastAPI,
    client: httpx.AsyncClient,
) -> None:
    """Assert expired device codes cannot be exchanged."""
    await create_device_client(app)
    authorization_response = await request_device_authorization(client)
    async with app.state.core_session_factory() as db_session:
        await db_session.execute(
            update(OAuth2DeviceAuthorizationDB).values(
                expires_at=datetime.now(UTC) - timedelta(seconds=1)
            )
        )
        await db_session.commit()

    response = await poll_device_code(
        client,
        device_code=authorization_response.json()["device_code"],
    )

    assert response.status_code == status.HTTP_400_BAD_REQUEST
    assert response.json()["error"] == "expired_token"


@pytest.mark.asyncio
@pytest.mark.negative
async def test_device_code_rejects_wrong_client(
    app: FastAPI,
    client: httpx.AsyncClient,
) -> None:
    """Assert a device code is bound to the client that created it."""
    await create_device_client(app)
    await create_device_client(app, client_id="other-device-client")
    authorization_response = await request_device_authorization(client)

    response = await poll_device_code(
        client,
        device_code=authorization_response.json()["device_code"],
        client_id="other-device-client",
    )

    assert response.status_code == status.HTTP_400_BAD_REQUEST
    assert response.json()["error"] == "invalid_grant"


@pytest.mark.asyncio
@pytest.mark.negative
async def test_device_authorization_rejects_invalid_scope(
    app: FastAPI,
    client: httpx.AsyncClient,
) -> None:
    """Assert device authorization rejects scopes outside registration."""
    await create_device_client(app)

    response = await request_device_authorization(client, scope="write")

    assert response.status_code == status.HTTP_400_BAD_REQUEST
    assert response.json()["error"] == "invalid_scope"


@pytest.mark.asyncio
@pytest.mark.negative
async def test_device_authorization_rejects_openid_scope(
    app: FastAPI,
    client: httpx.AsyncClient,
) -> None:
    """Keep the device grant OAuth2-only even when OIDC is enabled."""
    await create_device_client(app, scopes=["read", "openid"])

    response = await request_device_authorization(client, scope="openid")

    assert response.status_code == status.HTTP_400_BAD_REQUEST
    assert response.json()["error"] == "invalid_scope"


@pytest.mark.asyncio
@pytest.mark.negative
async def test_device_polling_rejects_persisted_openid_scope(
    app: FastAPI,
    client: httpx.AsyncClient,
    verified_user_credentials: UserCredentials,
) -> None:
    """Revalidate the OAuth2-only scope policy before token issuance."""
    await create_device_client(app, scopes=["read", "openid"])
    authorization_response = await request_device_authorization(client)
    device_body = authorization_response.json()
    async with app.state.core_session_factory() as db_session:
        await db_session.execute(
            update(OAuth2DeviceAuthorizationDB).values(scope="openid")
        )
        await db_session.commit()
    approval_response = await approve_user_code(
        app,
        client,
        user_code=device_body["user_code"],
        credentials=verified_user_credentials,
    )
    assert approval_response.status_code == status.HTTP_200_OK

    response = await poll_device_code(
        client,
        device_code=device_body["device_code"],
    )

    assert response.status_code == status.HTTP_400_BAD_REQUEST
    assert response.json()["error"] == "invalid_scope"


@pytest.mark.asyncio
@pytest.mark.negative
async def test_device_authorization_rejects_inactive_client(
    app: FastAPI,
    client: httpx.AsyncClient,
) -> None:
    """Assert inactive device clients cannot start device authorization."""
    await create_device_client(app, is_active=False)

    response = await request_device_authorization(client)

    assert response.status_code == status.HTTP_401_UNAUTHORIZED
    assert response.json()["error"] == "invalid_client"


@pytest.mark.asyncio
@pytest.mark.negative
async def test_device_authorization_rejects_client_without_device_grant(
    app: FastAPI,
    client: httpx.AsyncClient,
) -> None:
    """Assert device authorization requires the device grant registration."""
    async with app.state.core_session_factory() as db_session:
        db_session.add(
            OAuth2ClientDB(
                client_id="browser-only-client",
                client_secret=None,
                name="Browser Only Client",
                grant_types=["authorization_code"],
                scopes=["read"],
                redirect_uris=["https://client.example/callback"],
                is_confidential=False,
                is_active=True,
            )
        )
        await db_session.commit()

    response = await request_device_authorization(
        client,
        client_id="browser-only-client",
    )

    assert response.status_code == status.HTTP_400_BAD_REQUEST
    assert response.json()["error"] == "unauthorized_client"


@app_settings(oauth2={"allow_client_secret_post": True})
@pytest.mark.asyncio
@pytest.mark.negative
async def test_device_authorization_rejects_wrong_confidential_secret(
    app: FastAPI,
    client: httpx.AsyncClient,
) -> None:
    """Assert confidential device authorization rejects a wrong secret."""
    await create_device_client(app, is_confidential=True)

    response = await request_device_authorization(
        client,
        client_secret="wrong-secret",  # noqa: S106
    )

    assert response.status_code == status.HTTP_401_UNAUTHORIZED
    assert response.json()["error"] == "invalid_client"


@app_settings(oauth2={"allow_client_secret_post": True})
@pytest.mark.asyncio
@pytest.mark.negative
@pytest.mark.parametrize("supplied_secret", ["invented-secret", ""])
async def test_device_authorization_rejects_secret_for_public_client(
    app: FastAPI,
    client: httpx.AsyncClient,
    supplied_secret: str,
) -> None:
    """Reject non-empty and empty secrets supplied for a public client."""
    await create_device_client(app)

    response = await request_device_authorization(
        client,
        client_secret=supplied_secret,
    )

    assert response.status_code == status.HTTP_401_UNAUTHORIZED
    assert response.json()["error"] == "invalid_client"


@app_settings(oauth2={"allow_client_secret_post": False})
@pytest.mark.asyncio
@pytest.mark.negative
async def test_device_authorization_rejects_disabled_client_secret_post(
    app: FastAPI,
    client: httpx.AsyncClient,
) -> None:
    """Reject confidential client credentials in the request body by policy."""
    raw_secret = await create_device_client(app, is_confidential=True)
    assert raw_secret is not None

    response = await request_device_authorization(
        client,
        client_secret=raw_secret,
    )

    assert response.status_code == status.HTTP_400_BAD_REQUEST
    assert response.json()["error"] == "invalid_request"


@pytest.mark.asyncio
async def test_device_authorization_retries_user_code_collision(
    app: FastAPI,
    client: httpx.AsyncClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Assert device authorization retries when generated user codes collide."""
    await create_device_client(app)
    token_hash_secret = app.state.settings.oauth2.token_hash_secret.get_secret_value()
    async with app.state.core_session_factory() as db_session:
        db_session.add(
            OAuth2DeviceAuthorizationDB(
                device_code_hash=hash_oauth2_token(
                    token="existing-device-code",  # noqa: S106
                    secret=token_hash_secret,
                ),
                user_code_hash=hash_oauth2_token(
                    token="COLL-IDE1",  # noqa: S106
                    secret=token_hash_secret,
                ),
                client_id="device-client",
                scope="read",
                expires_at=datetime.now(UTC) + timedelta(minutes=5),
                interval_seconds=5,
                organization_id=None,
            )
        )
        await db_session.commit()

    generated_codes = iter(["COLL-IDE1", "NEXT-CODE"])
    monkeypatch.setattr(
        "app.oauth2.devices.authorization.create_user_code",
        lambda: next(generated_codes),
    )

    response = await request_device_authorization(client)

    assert response.status_code == status.HTTP_200_OK
    assert response.json()["user_code"] == "NEXT-CODE"
    async with app.state.core_session_factory() as db_session:
        count = await db_session.scalar(
            select(func.count()).select_from(OAuth2DeviceAuthorizationDB)
        )
    assert count == EXPECTED_DEVICE_AUTHORIZATIONS_AFTER_RETRY


@pytest.mark.asyncio
@pytest.mark.negative
async def test_device_authorization_rejects_confidential_client_without_secret(
    app: FastAPI,
    client: httpx.AsyncClient,
) -> None:
    """Assert confidential device clients authenticate during authorization."""
    await create_device_client(app, is_confidential=True)

    response = await request_device_authorization(client)

    assert response.status_code == status.HTTP_401_UNAUTHORIZED
    assert response.json()["error"] == "invalid_client"


@app_settings(oauth2={"allow_client_secret_post": True})
@pytest.mark.asyncio
@pytest.mark.negative
async def test_device_code_rejects_confidential_client_without_secret(
    app: FastAPI,
    client: httpx.AsyncClient,
) -> None:
    """Assert confidential device clients authenticate during token polling."""
    raw_secret = await create_device_client(app, is_confidential=True)
    assert raw_secret is not None
    authorization_response = await request_device_authorization(
        client,
        client_secret=raw_secret,
    )
    assert authorization_response.status_code == status.HTTP_200_OK

    response = await poll_device_code(
        client,
        device_code=authorization_response.json()["device_code"],
    )

    assert response.status_code == status.HTTP_401_UNAUTHORIZED


@pytest.mark.asyncio
@pytest.mark.negative
async def test_device_code_rejects_inactive_client_after_approval(
    app: FastAPI,
    client: httpx.AsyncClient,
    verified_user_credentials: UserCredentials,
) -> None:
    """Assert device-code exchange rechecks client activity after approval."""
    await create_device_client(app)
    authorization_response = await request_device_authorization(client)
    device_body = authorization_response.json()
    approval_response = await approve_user_code(
        app,
        client,
        user_code=device_body["user_code"],
        credentials=verified_user_credentials,
    )
    assert approval_response.status_code == status.HTTP_200_OK
    async with app.state.core_session_factory() as db_session:
        await db_session.execute(
            update(OAuth2ClientDB)
            .where(OAuth2ClientDB.client_id == "device-client")
            .values(is_active=False)
        )
        await db_session.commit()

    response = await poll_device_code(
        client,
        device_code=device_body["device_code"],
    )

    assert response.status_code == status.HTTP_401_UNAUTHORIZED
    assert response.json()["error"] == "invalid_client"


@pytest.mark.asyncio
@pytest.mark.negative
async def test_device_code_rejects_inactive_client_before_approval(
    app: FastAPI,
    client: httpx.AsyncClient,
) -> None:
    """Assert device polling rejects inactive clients before pending-state checks."""
    await create_device_client(app)
    authorization_response = await request_device_authorization(client)
    device_body = authorization_response.json()
    async with app.state.core_session_factory() as db_session:
        await db_session.execute(
            update(OAuth2ClientDB)
            .where(OAuth2ClientDB.client_id == "device-client")
            .values(is_active=False)
        )
        await db_session.commit()

    response = await poll_device_code(
        client,
        device_code=device_body["device_code"],
    )

    assert response.status_code == status.HTTP_401_UNAUTHORIZED
    assert response.json()["error"] == "invalid_client"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("is_active", "email_verified"),
    [
        pytest.param(False, True, id="inactive"),
        pytest.param(True, False, id="unverified"),
    ],
)
@pytest.mark.negative
async def test_device_code_rejects_blocked_user_after_approval(
    app: FastAPI,
    client: httpx.AsyncClient,
    verified_user_credentials: UserCredentials,
    is_active: bool,  # noqa: FBT001
    email_verified: bool,  # noqa: FBT001
) -> None:
    """Assert device-code exchange rejects users blocked after approval."""
    await create_device_client(app)
    authorization_response = await request_device_authorization(client)
    device_body = authorization_response.json()
    approval_response = await approve_user_code(
        app,
        client,
        user_code=device_body["user_code"],
        credentials=verified_user_credentials,
    )
    assert approval_response.status_code == status.HTTP_200_OK
    async with app.state.core_session_factory() as db_session:
        await db_session.execute(
            update(UserDB)
            .where(
                UserDB.id == current_user_id_for_email(verified_user_credentials.email)
            )
            .values(is_active=is_active)
        )
        if not email_verified:
            await db_session.execute(
                update(UserEmailDB)
                .where(
                    UserEmailDB.normalized_email
                    == verified_user_credentials.email.lower(),
                    UserEmailDB.status == UserEmailStatus.CURRENT,
                )
                .values(verified_at=None)
            )
        await db_session.commit()

    response = await poll_device_code(
        client,
        device_code=device_body["device_code"],
    )

    assert response.status_code == status.HTTP_400_BAD_REQUEST
    assert response.json()["error"] == "invalid_grant"


@pytest.mark.asyncio
@pytest.mark.negative
async def test_device_verify_rejects_missing_csrf_protection(
    app: FastAPI,
    client: httpx.AsyncClient,
    verified_user_credentials: UserCredentials,
) -> None:
    """Assert device approval rejects requests without CSRF protection."""
    await create_device_client(app)
    authorization_response = await request_device_authorization(client)

    response = await approve_user_code(
        app,
        client,
        user_code=authorization_response.json()["user_code"],
        credentials=verified_user_credentials,
        include_csrf=False,
    )

    assert response.status_code == status.HTTP_403_FORBIDDEN


@pytest.mark.asyncio
@pytest.mark.negative
async def test_device_verify_rejects_invalid_user_code(
    app: FastAPI,
    client: httpx.AsyncClient,
    verified_user_credentials: UserCredentials,
) -> None:
    """Assert device approval reports invalid user codes."""
    await create_device_client(app)

    response = await approve_user_code(
        app,
        client,
        user_code="BAD-CODE",
        credentials=verified_user_credentials,
    )

    assert response.status_code == status.HTTP_400_BAD_REQUEST
    assert "Invalid or expired code" in response.text
