"""Black-box tests for external OAuth2 interaction JSON contracts."""

from datetime import datetime, timedelta, UTC
from typing import cast
from urllib.parse import parse_qs, urlparse

import httpx
import pytest
from app.db.models.oauth2_authorization_transaction import (
    OAuth2AuthorizationTransactionDB,
)
from app.db.models.oauth2_client import OAuth2ClientDB
from app.db.models.oauth2_device_authorization import OAuth2DeviceAuthorizationDB
from app.db.models.organization import OrganizationDB
from app.db.models.user import UserDB
from app.oauth2.authorization.code import create_s256_code_challenge
from app.password.pwdlib_hasher import PwdlibPasswordHasher
from fastapi import FastAPI, status
from sqlalchemy import insert, update

from tests.fixtures.auth import login_browser, UserCredentials
from tests.fixtures.oauth2 import create_public_authorization_code_client
from tests.fixtures.settings import app_settings
from tests.identifiers import deterministic_uuid


pytestmark = pytest.mark.api
EXTERNAL_INTERACTION_URL = "https://frontend.example/oauth2/interaction"
REDIRECT_URI = "https://client.example/callback"
CODE_VERIFIER = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~"
DEVICE_GRANT_TYPE = "urn:ietf:params:oauth:grant-type:device_code"


def _authorization_parameters(
    *, client_id: str = str(deterministic_uuid("public-client"))
) -> dict[str, str]:
    """Return a valid public Authorization Code request."""

    return {
        "response_type": "code",
        "client_id": client_id,
        "redirect_uri": REDIRECT_URI,
        "scope": "read",
        "state": "external-state",
        "code_challenge": create_s256_code_challenge(code_verifier=CODE_VERIFIER),
        "code_challenge_method": "S256",
    }


def _interaction_id(response: httpx.Response, parameter: str) -> str:
    """Extract an opaque interaction identifier from a redirect."""
    return parse_qs(urlparse(response.headers["location"]).query)[parameter][0]


def _session_headers(app: FastAPI, login_response: httpx.Response) -> dict[str, str]:
    """Return the origin and current session CSRF header."""
    header_name = app.state.settings.browser_session.csrf.header_name
    return {
        "Origin": "http://testserver",
        header_name: login_response.headers[header_name],
    }


async def _create_device_client(app: FastAPI) -> None:
    """Persist a public client supporting Device Code."""
    async with app.state.core_session_factory() as db_session:
        db_session.add(
            OAuth2ClientDB(
                client_id=deterministic_uuid("device-client"),
                client_secret=None,
                name="Device Client",
                grant_types=[DEVICE_GRANT_TYPE, "refresh_token"],
                scopes=["read"],
                redirect_uris=[],
                is_confidential=False,
                is_active=True,
            )
        )
        await db_session.commit()


async def _create_no_consent_client(app: FastAPI) -> None:
    """Persist a public Authorization Code client with implicit consent."""
    async with app.state.core_session_factory() as db_session:
        db_session.add(
            OAuth2ClientDB(
                client_id=deterministic_uuid("no-consent-client"),
                client_secret=None,
                name="No Consent Client",
                grant_types=["authorization_code"],
                scopes=["read"],
                redirect_uris=[REDIRECT_URI],
                is_confidential=False,
                requires_consent=False,
                is_active=True,
            )
        )
        await db_session.commit()


async def _start_device_authorization(
    app: FastAPI, client: httpx.AsyncClient
) -> dict[str, object]:
    """Create one external Device Code interaction and return its response body."""
    await _create_device_client(app)
    response = await client.post(
        "/oauth2/device_authorization",
        data={"client_id": str(deterministic_uuid("device-client")), "scope": "read"},
    )
    assert response.status_code == status.HTTP_200_OK
    return cast("dict[str, object]", response.json())


@pytest.mark.asyncio
@app_settings(
    ui={
        "oauth2_interaction": "external",
        "urls": {
            "authorization_interaction": EXTERNAL_INTERACTION_URL,
            "device_interaction": EXTERNAL_INTERACTION_URL,
        },
    },
)
async def test_authorization_interaction_requires_session_and_is_consumed_once(
    app: FastAPI,
    client: httpx.AsyncClient,
    verified_user_credentials: UserCredentials,
) -> None:
    """Expose consent safely and consume one approved decision exactly once."""
    await create_public_authorization_code_client(app)
    start = await client.get(
        "/oauth2/authorize",
        params=_authorization_parameters(),
        follow_redirects=False,
    )

    assert start.status_code == status.HTTP_303_SEE_OTHER
    assert urlparse(start.headers["location"]).path == "/oauth2/interaction"
    transaction_id = _interaction_id(start, "transaction_id")
    interaction_path = f"/api/v1/oauth2/authorization-interactions/{transaction_id}"

    anonymous = await client.post(interaction_path)
    assert anonymous.status_code == status.HTTP_401_UNAUTHORIZED
    assert anonymous.headers["cache-control"] == "no-store"

    login_response = await login_browser(client, verified_user_credentials)
    missing_continue_csrf = await client.post(interaction_path)
    assert missing_continue_csrf.status_code == status.HTTP_403_FORBIDDEN
    assert missing_continue_csrf.headers["cache-control"] == "no-store"

    interaction = await client.post(
        interaction_path,
        headers=_session_headers(app, login_response),
    )

    assert interaction.status_code == status.HTTP_200_OK
    assert interaction.headers["cache-control"] == "no-store"
    assert interaction.json() == {
        "action": "consent_required",
        "client_name": "Public Client",
        "scopes": ["read"],
    }

    missing_csrf = await client.post(
        f"{interaction_path}/decision",
        json={"decision": "approve"},
    )
    assert missing_csrf.status_code == status.HTTP_403_FORBIDDEN
    assert missing_csrf.headers["cache-control"] == "no-store"

    decision = await client.post(
        f"{interaction_path}/decision",
        json={"decision": "approve"},
        headers=_session_headers(app, login_response),
    )
    assert decision.status_code == status.HTTP_200_OK
    assert decision.headers["cache-control"] == "no-store"
    redirect = urlparse(decision.json()["redirect_url"])
    assert f"{redirect.scheme}://{redirect.netloc}{redirect.path}" == REDIRECT_URI
    assert parse_qs(redirect.query)["state"] == ["external-state"]
    assert "code" in parse_qs(redirect.query)

    repeated = await client.post(
        f"{interaction_path}/decision",
        json={"decision": "approve"},
        headers=_session_headers(app, login_response),
    )
    assert repeated.status_code == status.HTTP_400_BAD_REQUEST
    assert repeated.json()["code"] == "OAUTH2_INTERACTION_INVALID"
    assert repeated.headers["cache-control"] == "no-store"


@pytest.mark.asyncio
@app_settings(
    ui={
        "oauth2_interaction": "external",
        "urls": {
            "authorization_interaction": EXTERNAL_INTERACTION_URL,
            "device_interaction": EXTERNAL_INTERACTION_URL,
        },
    },
)
async def test_authorization_interaction_denial_returns_oauth2_redirect(
    app: FastAPI,
    client: httpx.AsyncClient,
    verified_user_credentials: UserCredentials,
) -> None:
    """Keep the OAuth2 error response in the validated client redirect."""
    await create_public_authorization_code_client(app)
    start = await client.get(
        "/oauth2/authorize",
        params=_authorization_parameters(),
        follow_redirects=False,
    )
    transaction_id = _interaction_id(start, "transaction_id")
    login_response = await login_browser(client, verified_user_credentials)
    interaction_path = f"/api/v1/oauth2/authorization-interactions/{transaction_id}"
    assert (
        await client.post(
            interaction_path,
            headers=_session_headers(app, login_response),
        )
    ).status_code == status.HTTP_200_OK

    decision = await client.post(
        f"{interaction_path}/decision",
        json={"decision": "deny"},
        headers=_session_headers(app, login_response),
    )

    query = parse_qs(urlparse(decision.json()["redirect_url"]).query)
    assert decision.status_code == status.HTTP_200_OK
    assert query["error"] == ["access_denied"]
    assert query["state"] == ["external-state"]


@pytest.mark.asyncio
@app_settings(
    ui={
        "oauth2_interaction": "external",
        "urls": {
            "authorization_interaction": EXTERNAL_INTERACTION_URL,
            "device_interaction": EXTERNAL_INTERACTION_URL,
        },
    },
)
async def test_authorization_interaction_without_consent_returns_redirect(
    app: FastAPI,
    client: httpx.AsyncClient,
    verified_user_credentials: UserCredentials,
) -> None:
    """Issue and consume an authorization response during interaction lookup."""
    await _create_no_consent_client(app)
    start = await client.get(
        "/oauth2/authorize",
        params=_authorization_parameters(
            client_id=deterministic_uuid("no-consent-client")
        ),
        follow_redirects=False,
    )
    transaction_id = _interaction_id(start, "transaction_id")
    login_response = await login_browser(client, verified_user_credentials)
    interaction_path = f"/api/v1/oauth2/authorization-interactions/{transaction_id}"

    interaction = await client.post(
        interaction_path,
        headers=_session_headers(app, login_response),
    )
    assert interaction.status_code == status.HTTP_200_OK
    assert interaction.json()["action"] == "redirect"
    assert "code" in parse_qs(urlparse(interaction.json()["redirect_url"]).query)

    repeated = await client.post(
        interaction_path,
        headers=_session_headers(app, login_response),
    )
    assert repeated.status_code == status.HTTP_400_BAD_REQUEST
    assert repeated.json()["code"] == "OAUTH2_INTERACTION_INVALID"


@pytest.mark.asyncio
@app_settings(
    ui={
        "oauth2_interaction": "external",
        "urls": {
            "authorization_interaction": EXTERNAL_INTERACTION_URL,
            "device_interaction": EXTERNAL_INTERACTION_URL,
        },
    },
)
async def test_expired_authorization_interaction_is_generic(
    app: FastAPI,
    client: httpx.AsyncClient,
    verified_user_credentials: UserCredentials,
) -> None:
    """Hide an expired transaction behind the common interaction error."""
    await create_public_authorization_code_client(app)
    start = await client.get(
        "/oauth2/authorize",
        params=_authorization_parameters(),
        follow_redirects=False,
    )
    transaction_id = _interaction_id(start, "transaction_id")
    async with app.state.core_session_factory() as db_session:
        await db_session.execute(
            update(OAuth2AuthorizationTransactionDB).values(
                expires_at=datetime.now(UTC) - timedelta(seconds=1)
            )
        )
        await db_session.commit()
    login_response = await login_browser(client, verified_user_credentials)

    response = await client.post(
        f"/api/v1/oauth2/authorization-interactions/{transaction_id}",
        headers=_session_headers(app, login_response),
    )

    assert response.status_code == status.HTTP_400_BAD_REQUEST
    assert response.json()["code"] == "OAUTH2_INTERACTION_INVALID"


@pytest.mark.asyncio
@app_settings(
    ui={
        "oauth2_interaction": "external",
        "urls": {
            "authorization_interaction": EXTERNAL_INTERACTION_URL,
            "device_interaction": EXTERNAL_INTERACTION_URL,
        },
    },
)
async def test_foreign_authorization_interaction_is_generic(
    app: FastAPI,
    client: httpx.AsyncClient,
    verified_user_credentials: UserCredentials,
) -> None:
    """Do not disclose a transaction already bound to another identity."""
    await create_public_authorization_code_client(app)
    start = await client.get(
        "/oauth2/authorize",
        params=_authorization_parameters(),
        follow_redirects=False,
    )
    transaction_id = _interaction_id(start, "transaction_id")
    async with app.state.core_session_factory() as db_session:
        foreign_organization_id = (
            await db_session.execute(
                insert(OrganizationDB)
                .values(name="Foreign Organization")
                .returning(OrganizationDB.id)
            )
        ).scalar_one()
        foreign_user_id = (
            await db_session.execute(
                insert(UserDB)
                .values(
                    first_name="Foreign",
                    last_name="User",
                    hashed_password=PwdlibPasswordHasher().hash("ForeignPass1!"),
                    is_active=True,
                    is_operator=False,
                )
                .returning(UserDB.id)
            )
        ).scalar_one()
        await db_session.execute(
            update(OAuth2AuthorizationTransactionDB).values(
                user_id=foreign_user_id,
                organization_id=foreign_organization_id,
            )
        )
        await db_session.commit()
    login_response = await login_browser(client, verified_user_credentials)

    response = await client.post(
        f"/api/v1/oauth2/authorization-interactions/{transaction_id}",
        headers=_session_headers(app, login_response),
    )

    assert response.status_code == status.HTTP_400_BAD_REQUEST
    assert response.json()["code"] == "OAUTH2_INTERACTION_INVALID"


@pytest.mark.asyncio
@app_settings(
    ui={
        "oauth2_interaction": "external",
        "urls": {
            "authorization_interaction": EXTERNAL_INTERACTION_URL,
            "device_interaction": EXTERNAL_INTERACTION_URL,
        },
    },
)
async def test_changed_organization_policy_returns_oauth2_denial(
    app: FastAPI,
    client: httpx.AsyncClient,
    verified_user_credentials: UserCredentials,
) -> None:
    """Re-evaluate client organization policy when the decision is submitted."""
    await create_public_authorization_code_client(app)
    start = await client.get(
        "/oauth2/authorize",
        params=_authorization_parameters(),
        follow_redirects=False,
    )
    transaction_id = _interaction_id(start, "transaction_id")
    login_response = await login_browser(client, verified_user_credentials)
    interaction_path = f"/api/v1/oauth2/authorization-interactions/{transaction_id}"
    assert (
        await client.post(
            interaction_path,
            headers=_session_headers(app, login_response),
        )
    ).status_code == status.HTTP_200_OK
    async with app.state.core_session_factory() as db_session:
        await db_session.execute(
            update(OAuth2ClientDB)
            .where(OAuth2ClientDB.client_id == deterministic_uuid("public-client"))
            .values(user_organization_access="selected")
        )
        await db_session.commit()

    response = await client.post(
        f"{interaction_path}/decision",
        json={"decision": "approve"},
        headers=_session_headers(app, login_response),
    )

    query = parse_qs(urlparse(response.json()["redirect_url"]).query)
    assert response.status_code == status.HTTP_200_OK
    assert query["error"] == ["access_denied"]


@pytest.mark.asyncio
@app_settings(
    ui={
        "oauth2_interaction": "external",
        "urls": {
            "authorization_interaction": EXTERNAL_INTERACTION_URL,
            "device_interaction": EXTERNAL_INTERACTION_URL,
        },
    },
)
async def test_device_interaction_uses_external_uri_and_records_decision(
    app: FastAPI,
    client: httpx.AsyncClient,
    verified_user_credentials: UserCredentials,
) -> None:
    """Publish the external verification URI and protect its JSON decision."""
    body = await _start_device_authorization(app, client)
    assert body["verification_uri"] == EXTERNAL_INTERACTION_URL
    complete = urlparse(str(body["verification_uri_complete"]))
    assert parse_qs(complete.query)["user_code"] == [body["user_code"]]

    interaction_path = f"/api/v1/oauth2/device-interactions/{body['user_code']}"
    anonymous = await client.get(interaction_path)
    assert anonymous.status_code == status.HTTP_401_UNAUTHORIZED
    assert anonymous.headers["cache-control"] == "no-store"

    login_response = await login_browser(client, verified_user_credentials)
    interaction = await client.get(interaction_path)
    assert interaction.status_code == status.HTTP_200_OK
    assert interaction.headers["cache-control"] == "no-store"
    assert interaction.json() == {
        "client_name": "Device Client",
        "scopes": ["read"],
    }

    missing_csrf = await client.post(
        f"{interaction_path}/decision",
        json={"decision": "approve"},
    )
    assert missing_csrf.status_code == status.HTTP_403_FORBIDDEN
    assert missing_csrf.headers["cache-control"] == "no-store"

    decision = await client.post(
        f"{interaction_path}/decision",
        json={"decision": "approve"},
        headers=_session_headers(app, login_response),
    )
    assert decision.status_code == status.HTTP_204_NO_CONTENT
    assert decision.headers["cache-control"] == "no-store"

    repeated = await client.post(
        f"{interaction_path}/decision",
        json={"decision": "deny"},
        headers=_session_headers(app, login_response),
    )
    assert repeated.status_code == status.HTTP_400_BAD_REQUEST
    assert repeated.json()["code"] == "OAUTH2_INTERACTION_INVALID"


@pytest.mark.asyncio
@app_settings(
    ui={
        "oauth2_interaction": "external",
        "urls": {
            "authorization_interaction": EXTERNAL_INTERACTION_URL,
            "device_interaction": EXTERNAL_INTERACTION_URL,
        },
    },
)
async def test_device_interaction_records_denial_once(
    app: FastAPI,
    client: httpx.AsyncClient,
    verified_user_credentials: UserCredentials,
) -> None:
    """Consume a denied Device Code interaction without revealing token state."""
    body = await _start_device_authorization(app, client)
    login_response = await login_browser(client, verified_user_credentials)
    interaction_path = f"/api/v1/oauth2/device-interactions/{body['user_code']}"

    decision = await client.post(
        f"{interaction_path}/decision",
        json={"decision": "deny"},
        headers=_session_headers(app, login_response),
    )
    repeated = await client.get(interaction_path)

    assert decision.status_code == status.HTTP_204_NO_CONTENT
    assert repeated.status_code == status.HTTP_400_BAD_REQUEST
    assert repeated.json()["code"] == "OAUTH2_INTERACTION_INVALID"


@pytest.mark.asyncio
@app_settings(
    ui={
        "oauth2_interaction": "external",
        "urls": {
            "authorization_interaction": EXTERNAL_INTERACTION_URL,
            "device_interaction": EXTERNAL_INTERACTION_URL,
        },
    },
)
async def test_expired_device_interaction_is_generic(
    app: FastAPI,
    client: httpx.AsyncClient,
    verified_user_credentials: UserCredentials,
) -> None:
    """Hide an expired Device Code behind the common interaction error."""
    body = await _start_device_authorization(app, client)
    async with app.state.core_session_factory() as db_session:
        await db_session.execute(
            update(OAuth2DeviceAuthorizationDB).values(
                expires_at=datetime.now(UTC) - timedelta(seconds=1)
            )
        )
        await db_session.commit()
    await login_browser(client, verified_user_credentials)

    response = await client.get(
        f"/api/v1/oauth2/device-interactions/{body['user_code']}"
    )

    assert response.status_code == status.HTTP_400_BAD_REQUEST
    assert response.json()["code"] == "OAUTH2_INTERACTION_INVALID"


@pytest.mark.asyncio
@app_settings(
    ui={
        "oauth2_interaction": "external",
        "urls": {
            "authorization_interaction": EXTERNAL_INTERACTION_URL,
            "device_interaction": EXTERNAL_INTERACTION_URL,
        },
    },
)
async def test_changed_organization_policy_invalidates_device_interaction(
    app: FastAPI,
    client: httpx.AsyncClient,
    verified_user_credentials: UserCredentials,
) -> None:
    """Re-evaluate Device Code organization policy before display and decision."""
    body = await _start_device_authorization(app, client)
    login_response = await login_browser(client, verified_user_credentials)
    interaction_path = f"/api/v1/oauth2/device-interactions/{body['user_code']}"
    assert (await client.get(interaction_path)).status_code == status.HTTP_200_OK
    async with app.state.core_session_factory() as db_session:
        await db_session.execute(
            update(OAuth2ClientDB)
            .where(OAuth2ClientDB.client_id == deterministic_uuid("device-client"))
            .values(user_organization_access="selected")
        )
        await db_session.commit()

    preview = await client.get(interaction_path)
    decision = await client.post(
        f"{interaction_path}/decision",
        json={"decision": "approve"},
        headers=_session_headers(app, login_response),
    )

    assert preview.status_code == status.HTTP_400_BAD_REQUEST
    assert preview.json()["code"] == "OAUTH2_INTERACTION_INVALID"
    assert decision.status_code == status.HTTP_400_BAD_REQUEST
    assert decision.json()["code"] == "OAUTH2_INTERACTION_INVALID"
