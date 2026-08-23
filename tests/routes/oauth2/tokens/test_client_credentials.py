"""Black-box HTTP tests for client-credentials grants and machine principals."""

import base64
from datetime import datetime, UTC

import httpx
import pytest
from app.db.models.oauth2_client import OAuth2ClientDB
from app.db.models.oauth2_session import OAuth2SessionDB
from app.db.models.oauth2_token_pair import OAuth2TokenPairDB
from fastapi import FastAPI, status
from sqlalchemy import select, update

from app.oauth2.clients import client_credentials as client_credentials_workflow
from tests.fixtures.oauth2 import (
    add_oauth2_principal_routes,
    create_confidential_authorization_code_client,
    create_confidential_machine_client,
    create_public_client_credentials_client,
    decode_unverified_jwt_payload,
)
from tests.fixtures.settings import app_settings


pytestmark = pytest.mark.api


@pytest.mark.asyncio
@app_settings(
    session={"enabled": False},
    ui={"oauth2_interaction": "disabled"},
    oauth2={
        "authorization_code_enabled": False,
        "device_code_enabled": False,
        "oidc_enabled": False,
    },
)
async def test_client_credentials_works_without_browser_sessions(
    app: FastAPI,
    client: httpx.AsyncClient,
) -> None:
    """Issue a machine token without browser-session infrastructure."""
    raw_secret = await create_confidential_machine_client(app)
    basic_payload = base64.b64encode(f"machine-client:{raw_secret}".encode()).decode()

    response = await client.post(
        "/oauth2/token",
        data={
            "grant_type": "client_credentials",
            "scope": "service:read",
        },
        headers={"Authorization": f"Basic {basic_payload}"},
    )

    assert response.status_code == status.HTTP_200_OK
    assert response.json()["access_token"]
    assert not hasattr(app.state, "memory_session_store")


@pytest.mark.asyncio
async def test_client_credentials_grant_issues_machine_access_token(
    app: FastAPI,
    client: httpx.AsyncClient,
) -> None:
    """Assert confidential machine clients can get client-credentials tokens."""
    raw_secret = await create_confidential_machine_client(app)
    basic_payload = base64.b64encode(f"machine-client:{raw_secret}".encode()).decode()

    response = await client.post(
        "/oauth2/token",
        data={
            "grant_type": "client_credentials",
            "scope": "service:read",
        },
        headers={"Authorization": f"Basic {basic_payload}"},
    )

    assert response.status_code == status.HTTP_200_OK
    body = response.json()
    assert body["access_token"]
    assert body["refresh_token"] is None
    claims = decode_unverified_jwt_payload(body["access_token"])
    assert claims["sub"] == "machine-client"
    assert claims["client_id"] == "machine-client"
    assert claims["scope"] == "service:read"
    assert "organization" not in claims
    async with app.state.core_session_factory() as db_session:
        token_pair = await db_session.scalar(select(OAuth2TokenPairDB))
        oauth2_session = await db_session.scalar(select(OAuth2SessionDB))
    assert token_pair is not None
    assert oauth2_session is not None
    assert oauth2_session.grant_type == "client_credentials"
    assert token_pair.refresh_token_hash is None
    assert token_pair.refresh_expires_at is None
    assert oauth2_session.organization_id is None


@pytest.mark.asyncio
@pytest.mark.negative
async def test_client_credentials_does_not_mask_internal_value_error(
    app: FastAPI,
    client: httpx.AsyncClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Let unexpected issuance defects escape the OAuth2 error mapping."""
    raw_secret = await create_confidential_machine_client(app)
    basic_payload = base64.b64encode(f"machine-client:{raw_secret}".encode()).decode()

    async def fail_issuance(*_args: object, **_kwargs: object) -> None:
        msg = "unexpected issuance defect"
        raise ValueError(msg)

    monkeypatch.setattr(
        client_credentials_workflow.TokenIssuanceService,
        "issue_new_session",
        fail_issuance,
    )

    with pytest.raises(ValueError, match="unexpected issuance defect"):
        await client.post(
            "/oauth2/token",
            data={
                "grant_type": "client_credentials",
                "scope": "service:read",
            },
            headers={"Authorization": f"Basic {basic_payload}"},
        )


@pytest.mark.asyncio
@app_settings(oauth2={"allow_client_secret_post": True})
async def test_client_credentials_allows_client_secret_post_when_enabled(
    app: FastAPI,
    client: httpx.AsyncClient,
) -> None:
    """Assert configured client_secret_post support accepts body credentials."""
    raw_secret = await create_confidential_machine_client(app)
    response = await client.post(
        "/oauth2/token",
        data={
            "grant_type": "client_credentials",
            "client_id": "machine-client",
            "client_secret": raw_secret,
            "scope": "service:read",
        },
    )

    assert response.status_code == status.HTTP_200_OK
    assert response.json()["access_token"]


@pytest.mark.asyncio
@app_settings(oauth2={"allow_client_secret_post": False})
@pytest.mark.negative
async def test_client_credentials_rejects_client_secret_post_when_disabled(
    app: FastAPI,
    client: httpx.AsyncClient,
) -> None:
    """Assert disabling client_secret_post rejects body client secrets."""
    raw_secret = await create_confidential_machine_client(app)
    response = await client.post(
        "/oauth2/token",
        data={
            "grant_type": "client_credentials",
            "client_id": "machine-client",
            "client_secret": raw_secret,
            "scope": "service:read",
        },
    )

    assert response.status_code == status.HTTP_400_BAD_REQUEST


@pytest.mark.asyncio
@pytest.mark.negative
async def test_client_credentials_rejects_wrong_secret(
    app: FastAPI,
    client: httpx.AsyncClient,
) -> None:
    """Assert client credentials rejects bad client secrets."""
    await create_confidential_machine_client(app)
    basic_payload = base64.b64encode(b"machine-client:wrong-secret").decode()

    response = await client.post(
        "/oauth2/token",
        data={
            "grant_type": "client_credentials",
            "scope": "service:read",
        },
        headers={"Authorization": f"Basic {basic_payload}"},
    )

    assert response.status_code == status.HTTP_401_UNAUTHORIZED


@pytest.mark.asyncio
@pytest.mark.negative
async def test_client_credentials_rejects_invalid_scope(
    app: FastAPI,
    client: httpx.AsyncClient,
) -> None:
    """Assert client credentials rejects scopes outside registration."""
    raw_secret = await create_confidential_machine_client(app)
    basic_payload = base64.b64encode(f"machine-client:{raw_secret}".encode()).decode()

    response = await client.post(
        "/oauth2/token",
        data={
            "grant_type": "client_credentials",
            "scope": "service:write",
        },
        headers={"Authorization": f"Basic {basic_payload}"},
    )

    assert response.status_code == status.HTTP_400_BAD_REQUEST


@pytest.mark.asyncio
@pytest.mark.negative
async def test_client_credentials_rejects_inactive_client(
    app: FastAPI,
    client: httpx.AsyncClient,
) -> None:
    """Assert inactive clients cannot use client credentials."""
    raw_secret = await create_confidential_machine_client(app)
    async with app.state.core_session_factory() as db_session:
        await db_session.execute(
            update(OAuth2ClientDB)
            .where(OAuth2ClientDB.client_id == "machine-client")
            .values(is_active=False)
        )
        await db_session.commit()
    basic_payload = base64.b64encode(f"machine-client:{raw_secret}".encode()).decode()

    response = await client.post(
        "/oauth2/token",
        data={
            "grant_type": "client_credentials",
            "scope": "service:read",
        },
        headers={"Authorization": f"Basic {basic_payload}"},
    )

    assert response.status_code == status.HTTP_401_UNAUTHORIZED


@pytest.mark.asyncio
@pytest.mark.negative
async def test_client_credentials_rejects_public_client(
    app: FastAPI,
    client: httpx.AsyncClient,
) -> None:
    """Assert client credentials requires a confidential client."""
    await create_public_client_credentials_client(app)

    response = await client.post(
        "/oauth2/token",
        data={
            "grant_type": "client_credentials",
            "client_id": "public-machine-client",
            "scope": "service:read",
        },
    )

    assert response.status_code == status.HTTP_400_BAD_REQUEST
    assert response.json()["error"] == "invalid_client"


@pytest.mark.asyncio
@pytest.mark.negative
async def test_client_credentials_rejects_client_without_grant(
    app: FastAPI,
    client: httpx.AsyncClient,
) -> None:
    """Assert confidential clients need the client-credentials grant registered."""
    raw_secret = await create_confidential_authorization_code_client(app)
    basic_payload = base64.b64encode(
        f"confidential-client:{raw_secret}".encode()
    ).decode()

    response = await client.post(
        "/oauth2/token",
        data={
            "grant_type": "client_credentials",
            "scope": "read",
        },
        headers={"Authorization": f"Basic {basic_payload}"},
    )

    assert response.status_code == status.HTTP_400_BAD_REQUEST
    assert response.json()["error"] == "unauthorized_client"


@pytest.mark.asyncio
async def test_client_credentials_token_resolves_machine_principal(
    app: FastAPI,
    client: httpx.AsyncClient,
) -> None:
    """Assert client-credentials tokens can authenticate as client principals."""
    add_oauth2_principal_routes(app)
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

    response = await client.get(
        "/test/oauth2/required-principal",
        headers={"Authorization": f"Bearer {token_response.json()['access_token']}"},
    )

    assert response.status_code == status.HTTP_200_OK
    assert response.json() == {
        "client_id": "machine-client",
        "user_id": None,
        "organization_id": None,
        "scopes": ["service:read"],
    }


@pytest.mark.asyncio
@pytest.mark.negative
async def test_userinfo_rejects_client_credentials_principal(
    app: FastAPI,
    client: httpx.AsyncClient,
) -> None:
    """Keep OIDC UserInfo restricted to user-backed bearer principals."""
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

    response = await client.get(
        "/oauth2/userinfo",
        headers={"Authorization": f"Bearer {token_response.json()['access_token']}"},
    )

    assert response.status_code == status.HTTP_401_UNAUTHORIZED
    assert response.json() == {"error": "invalid_token"}
    assert response.headers["WWW-Authenticate"] == "Bearer"


@pytest.mark.asyncio
async def test_client_credentials_token_enforces_scopes(
    app: FastAPI,
    client: httpx.AsyncClient,
) -> None:
    """Assert scope dependencies authorize machine clients by granted scope."""
    add_oauth2_principal_routes(app)
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

    read_response = await client.get(
        "/test/oauth2/scoped-principal",
        headers={"Authorization": f"Bearer {access_token}"},
    )
    write_response = await client.get(
        "/test/oauth2/write-scoped-principal",
        headers={"Authorization": f"Bearer {access_token}"},
    )

    assert read_response.status_code == status.HTTP_200_OK
    assert read_response.json()["client_id"] == "machine-client"
    assert write_response.status_code == status.HTTP_403_FORBIDDEN


@pytest.mark.asyncio
@pytest.mark.negative
async def test_client_credentials_principal_rejects_inactive_client_after_issue(
    app: FastAPI,
    client: httpx.AsyncClient,
) -> None:
    """Assert machine-principal resolution rechecks client activity."""
    add_oauth2_principal_routes(app)
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

    response = await client.get(
        "/test/oauth2/required-principal",
        headers={"Authorization": f"Bearer {token_response.json()['access_token']}"},
    )

    assert response.status_code == status.HTTP_401_UNAUTHORIZED


@pytest.mark.asyncio
@pytest.mark.negative
async def test_client_credentials_principal_rejects_ended_session(
    app: FastAPI,
    client: httpx.AsyncClient,
) -> None:
    """Assert machine-principal resolution requires a live OAuth2 session."""
    add_oauth2_principal_routes(app)
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
            update(OAuth2SessionDB).values(ended_at=datetime.now(UTC))
        )
        await db_session.commit()

    response = await client.get(
        "/test/oauth2/required-principal",
        headers={"Authorization": f"Bearer {token_response.json()['access_token']}"},
    )

    assert response.status_code == status.HTTP_401_UNAUTHORIZED
