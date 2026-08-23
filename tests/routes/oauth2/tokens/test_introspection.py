"""Black-box HTTP tests for token introspection and ownership rules."""

import base64
from datetime import datetime, timedelta, UTC

import httpx
import pytest
from app.db.models.oauth2_client import OAuth2ClientDB
from app.db.models.oauth2_session import OAuth2SessionDB
from app.db.models.oauth2_token_pair import OAuth2TokenPairDB
from fastapi import FastAPI, status
from sqlalchemy import update

from tests.fixtures.auth import UserCredentials
from tests.fixtures.oauth2 import (
    authorization_code_from_redirect,
    BEARER_TOKEN_TYPE,
    CODE_VERIFIER,
    create_confidential_authorization_code_client,
    create_confidential_machine_client,
    login_browser_session,
    PASSWORD_HASHER,
    request_authorization_code,
)


pytestmark = pytest.mark.api


@pytest.mark.asyncio
@pytest.mark.system
async def test_introspection_returns_active_client_owned_access_token(
    app: FastAPI,
    client: httpx.AsyncClient,
) -> None:
    """Assert a client can introspect its own active access token."""
    raw_secret = await create_confidential_machine_client(app)
    basic_payload = base64.b64encode(f"machine-client:{raw_secret}".encode()).decode()
    token_response = await client.post(
        "/oauth2/token",
        data={
            "grant_type": "client_credentials",
            "scope": "service:read",
        },
        headers={"Authorization": f"Basic {basic_payload}"},
    )
    access_token = token_response.json()["access_token"]

    response = await client.post(
        "/oauth2/introspect",
        data={
            "token": access_token,
            "token_type_hint": "access_token",
        },
        headers={"Authorization": f"Basic {basic_payload}"},
    )

    assert response.status_code == status.HTTP_200_OK
    body = response.json()
    assert body["active"] is True
    assert body["client_id"] == "machine-client"
    assert body["sub"] == "machine-client"
    assert body["scope"] == "service:read"
    assert response.headers["Cache-Control"] == "no-store"
    assert response.headers["Pragma"] == "no-cache"


@pytest.mark.asyncio
@pytest.mark.system
async def test_introspection_returns_active_client_owned_refresh_token(
    app: FastAPI,
    client: httpx.AsyncClient,
    verified_user_credentials: UserCredentials,
) -> None:
    """Assert a client can introspect its own active refresh token."""
    raw_secret = await create_confidential_authorization_code_client(app)
    basic_payload = base64.b64encode(
        f"confidential-client:{raw_secret}".encode()
    ).decode()
    login_response = await login_browser_session(client, verified_user_credentials)
    assert login_response.status_code == status.HTTP_204_NO_CONTENT
    authorize_response = await request_authorization_code(
        client,
        login_response=login_response,
        client_id="confidential-client",
        redirect_uri="https://confidential.example/callback",
    )
    token_response = await client.post(
        "/oauth2/token",
        data={
            "grant_type": "authorization_code",
            "code": authorization_code_from_redirect(authorize_response),
            "redirect_uri": "https://confidential.example/callback",
            "code_verifier": CODE_VERIFIER,
        },
        headers={"Authorization": f"Basic {basic_payload}"},
    )

    response = await client.post(
        "/oauth2/introspect",
        data={
            "token": token_response.json()["refresh_token"],
            "token_type_hint": "refresh_token",
        },
        headers={"Authorization": f"Basic {basic_payload}"},
    )

    assert response.status_code == status.HTTP_200_OK
    body = response.json()
    assert body["active"] is True
    assert body["client_id"] == "confidential-client"
    assert body["token_type"] == BEARER_TOKEN_TYPE


@pytest.mark.asyncio
@pytest.mark.negative
async def test_introspection_returns_inactive_for_ended_oauth2_session(
    app: FastAPI,
    client: httpx.AsyncClient,
) -> None:
    """Assert ended OAuth2 sessions make their tokens introspect inactive."""
    raw_secret = await create_confidential_machine_client(app)
    basic_payload = base64.b64encode(f"machine-client:{raw_secret}".encode()).decode()
    token_response = await client.post(
        "/oauth2/token",
        data={
            "grant_type": "client_credentials",
            "scope": "service:read",
        },
        headers={"Authorization": f"Basic {basic_payload}"},
    )
    access_token = token_response.json()["access_token"]
    async with app.state.core_session_factory() as db_session:
        await db_session.execute(
            update(OAuth2SessionDB).values(ended_at=datetime.now(UTC))
        )
        await db_session.commit()

    response = await client.post(
        "/oauth2/introspect",
        data={
            "token": access_token,
            "token_type_hint": "access_token",
        },
        headers={"Authorization": f"Basic {basic_payload}"},
    )

    assert response.status_code == status.HTTP_200_OK
    assert response.json() == {"active": False}


@pytest.mark.asyncio
@pytest.mark.negative
async def test_introspection_returns_inactive_for_expired_access_token(
    app: FastAPI,
    client: httpx.AsyncClient,
) -> None:
    """Assert expired access tokens do not introspect as active refresh tokens."""
    raw_secret = await create_confidential_machine_client(app)
    basic_payload = base64.b64encode(f"machine-client:{raw_secret}".encode()).decode()
    token_response = await client.post(
        "/oauth2/token",
        data={
            "grant_type": "client_credentials",
            "scope": "service:read",
        },
        headers={"Authorization": f"Basic {basic_payload}"},
    )
    access_token = token_response.json()["access_token"]
    async with app.state.core_session_factory() as db_session:
        await db_session.execute(
            update(OAuth2TokenPairDB).values(
                access_expires_at=datetime.now(UTC) - timedelta(seconds=1)
            )
        )
        await db_session.commit()

    response = await client.post(
        "/oauth2/introspect",
        data={
            "token": access_token,
            "token_type_hint": "access_token",
        },
        headers={"Authorization": f"Basic {basic_payload}"},
    )

    assert response.status_code == status.HTTP_200_OK
    assert response.json() == {"active": False}


@pytest.mark.asyncio
@pytest.mark.negative
async def test_introspection_hides_tokens_owned_by_another_client(
    app: FastAPI,
    client: httpx.AsyncClient,
) -> None:
    """Assert introspection does not leak another client's token state."""
    raw_secret = await create_confidential_machine_client(app)
    other_secret = "other-machine-client-secret"  # noqa: S105
    async with app.state.core_session_factory() as db_session:
        db_session.add(
            OAuth2ClientDB(
                client_id="other-machine-client",
                client_secret=PASSWORD_HASHER.hash(other_secret),
                name="Other Machine Client",
                grant_types=["client_credentials"],
                scopes=["service:read"],
                redirect_uris=[],
                is_confidential=True,
                is_active=True,
            )
        )
        await db_session.commit()
    basic_payload = base64.b64encode(f"machine-client:{raw_secret}".encode()).decode()
    other_basic_payload = base64.b64encode(
        f"other-machine-client:{other_secret}".encode()
    ).decode()
    token_response = await client.post(
        "/oauth2/token",
        data={
            "grant_type": "client_credentials",
            "scope": "service:read",
        },
        headers={"Authorization": f"Basic {basic_payload}"},
    )

    response = await client.post(
        "/oauth2/introspect",
        data={
            "token": token_response.json()["access_token"],
            "token_type_hint": "access_token",
        },
        headers={"Authorization": f"Basic {other_basic_payload}"},
    )

    assert response.status_code == status.HTTP_200_OK
    assert response.json() == {"active": False}


@pytest.mark.asyncio
@pytest.mark.negative
async def test_introspection_rejects_inactive_client(
    app: FastAPI,
    client: httpx.AsyncClient,
) -> None:
    """Assert inactive clients cannot authenticate for introspection."""
    raw_secret = await create_confidential_machine_client(app)
    basic_payload = base64.b64encode(f"machine-client:{raw_secret}".encode()).decode()
    token_response = await client.post(
        "/oauth2/token",
        data={
            "grant_type": "client_credentials",
            "scope": "service:read",
        },
        headers={"Authorization": f"Basic {basic_payload}"},
    )
    async with app.state.core_session_factory() as db_session:
        await db_session.execute(
            update(OAuth2ClientDB)
            .where(OAuth2ClientDB.client_id == "machine-client")
            .values(is_active=False)
        )
        await db_session.commit()

    response = await client.post(
        "/oauth2/introspect",
        data={
            "token": token_response.json()["access_token"],
        },
        headers={"Authorization": f"Basic {basic_payload}"},
    )

    assert response.status_code == status.HTTP_401_UNAUTHORIZED
