"""Black-box HTTP tests for authorization-code exchange and OIDC issuance."""

import base64
from datetime import datetime, timedelta, UTC
from urllib.parse import parse_qs, urlparse

import httpx
import pytest
from app.db.models.browser_session import BrowserSessionDB
from app.db.models.oauth2_authorization_code import (
    OAuth2AuthorizationCodeDB,
)
from app.db.models.user import UserDB
from fastapi import FastAPI, status
from sqlalchemy import select, update

from app.oauth2.authorization import code_exchange as code_exchange_workflow
from tests.fixtures.auth import current_user_id_for_email, UserCredentials
from tests.fixtures.oauth2 import (
    authorization_code_from_redirect,
    BEARER_TOKEN_TYPE,
    CODE_VERIFIER,
    count_token_pairs,
    create_confidential_authorization_code_client,
    create_public_authorization_code_client,
    create_public_oidc_client,
    decode_unverified_jwt_payload,
    login_browser_session,
    request_authorization_code,
    request_user_token,
)
from tests.fixtures.settings import app_settings


pytestmark = pytest.mark.api


@pytest.mark.asyncio
@pytest.mark.system
async def test_authorization_code_exchange_issues_token_pair(
    app: FastAPI,
    client: httpx.AsyncClient,
    verified_user_credentials: UserCredentials,
) -> None:
    """Assert authorization code + PKCE can be exchanged for bearer tokens."""
    await create_public_authorization_code_client(app)
    login_response = await login_browser_session(client, verified_user_credentials)
    assert login_response.status_code == status.HTTP_204_NO_CONTENT
    authorize_response = await request_authorization_code(
        client, login_response=login_response
    )
    assert authorize_response.status_code == status.HTTP_302_FOUND

    response = await client.post(
        "/oauth2/token",
        data={
            "grant_type": "authorization_code",
            "code": authorization_code_from_redirect(authorize_response),
            "redirect_uri": "https://client.example/callback",
            "client_id": "public-client",
            "code_verifier": CODE_VERIFIER,
        },
    )

    assert response.status_code == status.HTTP_200_OK
    body = response.json()
    assert body["token_type"] == BEARER_TOKEN_TYPE
    assert body["access_token"]
    assert body["refresh_token"]
    claims = decode_unverified_jwt_payload(body["access_token"])
    assert claims["client_id"] == "public-client"
    assert claims["scope"] == "read"
    assert await count_token_pairs(app) == 1


@pytest.mark.asyncio
@pytest.mark.negative
async def test_authorization_code_exchange_does_not_mask_internal_value_error(
    app: FastAPI,
    client: httpx.AsyncClient,
    verified_user_credentials: UserCredentials,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Let unexpected issuance defects escape the OAuth2 error mapping."""
    await create_public_authorization_code_client(app)
    login_response = await login_browser_session(client, verified_user_credentials)
    authorize_response = await request_authorization_code(
        client, login_response=login_response
    )

    async def fail_issuance(*_args: object, **_kwargs: object) -> None:
        msg = "unexpected issuance defect"
        raise ValueError(msg)

    monkeypatch.setattr(
        code_exchange_workflow.TokenIssuanceService,
        "issue_new_session",
        fail_issuance,
    )

    with pytest.raises(ValueError, match="unexpected issuance defect"):
        await client.post(
            "/oauth2/token",
            data={
                "grant_type": "authorization_code",
                "code": authorization_code_from_redirect(authorize_response),
                "redirect_uri": "https://client.example/callback",
                "client_id": "public-client",
                "code_verifier": CODE_VERIFIER,
            },
        )


@pytest.mark.asyncio
@app_settings(oauth2={"oidc_enabled": False})
@pytest.mark.negative
async def test_authorization_code_exchange_rejects_openid_when_oidc_disabled(
    app: FastAPI,
    client: httpx.AsyncClient,
    verified_user_credentials: UserCredentials,
) -> None:
    """Assert openid scope is rejected while optional OIDC support is disabled."""
    await create_public_oidc_client(app)
    login_response = await login_browser_session(client, verified_user_credentials)
    assert login_response.status_code == status.HTTP_204_NO_CONTENT

    response = await request_authorization_code(
        client,
        login_response=login_response,
        client_id="oidc-client",
        redirect_uri="https://oidc.example/callback",
        scope="openid email",
    )

    assert response.status_code == status.HTTP_302_FOUND
    error_query = parse_qs(urlparse(response.headers["location"]).query)
    assert error_query["error"] == ["invalid_scope"]


@pytest.mark.asyncio
@app_settings(oauth2={"oidc_enabled": True})
@pytest.mark.system
async def test_authorization_code_exchange_issues_id_token_when_oidc_enabled(
    app: FastAPI,
    client: httpx.AsyncClient,
    verified_user_credentials: UserCredentials,
) -> None:
    """Assert OIDC code flow returns an ID token for openid scope."""
    await create_public_oidc_client(app)
    login_response = await login_browser_session(client, verified_user_credentials)
    assert login_response.status_code == status.HTTP_204_NO_CONTENT
    async with app.state.core_session_factory() as db_session:
        authenticated_at = await db_session.scalar(select(BrowserSessionDB.created_at))
    assert authenticated_at is not None
    if authenticated_at.tzinfo is None:
        authenticated_at = authenticated_at.replace(tzinfo=UTC)
    authorize_response = await request_authorization_code(
        client,
        login_response=login_response,
        client_id="oidc-client",
        redirect_uri="https://oidc.example/callback",
        scope="openid email profile",
    )
    assert authorize_response.status_code == status.HTTP_302_FOUND

    response = await client.post(
        "/oauth2/token",
        data={
            "grant_type": "authorization_code",
            "code": authorization_code_from_redirect(authorize_response),
            "redirect_uri": "https://oidc.example/callback",
            "client_id": "oidc-client",
            "code_verifier": CODE_VERIFIER,
        },
    )

    assert response.status_code == status.HTTP_200_OK
    body = response.json()
    assert body["id_token"]
    access_claims = decode_unverified_jwt_payload(body["access_token"])
    id_claims = decode_unverified_jwt_payload(body["id_token"])
    assert access_claims["scope"] == "openid email profile"
    assert id_claims["aud"] == "oidc-client"
    assert id_claims["sub"] == access_claims["sub"]
    assert id_claims["email"] == verified_user_credentials.email
    assert id_claims["auth_time"] == int(authenticated_at.timestamp())


@pytest.mark.asyncio
@app_settings(oauth2={"oidc_enabled": True})
@pytest.mark.negative
async def test_userinfo_requires_oidc_and_openid_scope(
    app: FastAPI,
    client: httpx.AsyncClient,
    verified_user_credentials: UserCredentials,
) -> None:
    """Assert userinfo returns OIDC claims for an openid access token."""
    await create_public_oidc_client(app)
    login_response = await login_browser_session(client, verified_user_credentials)
    assert login_response.status_code == status.HTTP_204_NO_CONTENT
    authorize_response = await request_authorization_code(
        client,
        login_response=login_response,
        client_id="oidc-client",
        redirect_uri="https://oidc.example/callback",
        scope="openid email",
    )
    token_response = await client.post(
        "/oauth2/token",
        data={
            "grant_type": "authorization_code",
            "code": authorization_code_from_redirect(authorize_response),
            "redirect_uri": "https://oidc.example/callback",
            "client_id": "oidc-client",
            "code_verifier": CODE_VERIFIER,
        },
    )
    assert token_response.status_code == status.HTTP_200_OK

    userinfo_response = await client.get(
        "/oauth2/userinfo",
        headers={"Authorization": f"Bearer {token_response.json()['access_token']}"},
    )

    assert userinfo_response.status_code == status.HTTP_200_OK
    body = userinfo_response.json()
    assert body["email"] == verified_user_credentials.email
    assert body["email_verified"] is True
    assert "name" not in body
    assert "given_name" not in body
    assert "family_name" not in body
    assert (
        body["sub"]
        == decode_unverified_jwt_payload(token_response.json()["access_token"])["sub"]
    )


@pytest.mark.asyncio
@app_settings(oauth2={"oidc_enabled": True})
@pytest.mark.negative
@pytest.mark.parametrize("method", ["GET", "POST"])
async def test_userinfo_rejects_access_token_without_openid_scope(
    app: FastAPI,
    client: httpx.AsyncClient,
    verified_user_credentials: UserCredentials,
    method: str,
) -> None:
    """Require openid scope for both UserInfo methods."""
    token_response = await request_user_token(app, client, verified_user_credentials)
    assert token_response.status_code == status.HTTP_200_OK

    response = await client.request(
        method,
        "/oauth2/userinfo",
        headers={"Authorization": f"Bearer {token_response.json()['access_token']}"},
    )

    assert response.status_code == status.HTTP_403_FORBIDDEN
    assert response.json()["error"] == "insufficient_scope"
    assert response.headers["WWW-Authenticate"] == 'Bearer scope="openid"'


@pytest.mark.asyncio
async def test_authorization_code_exchange_supports_confidential_client_basic_auth(
    app: FastAPI,
    client: httpx.AsyncClient,
    verified_user_credentials: UserCredentials,
) -> None:
    """Assert confidential clients can exchange codes with HTTP Basic auth."""
    raw_secret = await create_confidential_authorization_code_client(app)
    login_response = await login_browser_session(client, verified_user_credentials)
    assert login_response.status_code == status.HTTP_204_NO_CONTENT
    authorize_response = await request_authorization_code(
        client,
        login_response=login_response,
        client_id="confidential-client",
        redirect_uri="https://confidential.example/callback",
    )
    basic_payload = base64.b64encode(
        f"confidential-client:{raw_secret}".encode()
    ).decode()

    response = await client.post(
        "/oauth2/token",
        data={
            "grant_type": "authorization_code",
            "code": authorization_code_from_redirect(authorize_response),
            "redirect_uri": "https://confidential.example/callback",
            "code_verifier": CODE_VERIFIER,
        },
        headers={"Authorization": f"Basic {basic_payload}"},
    )

    assert response.status_code == status.HTTP_200_OK
    claims = decode_unverified_jwt_payload(response.json()["access_token"])
    assert claims["client_id"] == "confidential-client"


@pytest.mark.asyncio
@pytest.mark.negative
async def test_authorization_code_exchange_rejects_missing_confidential_secret(
    app: FastAPI,
    client: httpx.AsyncClient,
    verified_user_credentials: UserCredentials,
) -> None:
    """Assert confidential clients must authenticate during code exchange."""
    await create_confidential_authorization_code_client(app)
    login_response = await login_browser_session(client, verified_user_credentials)
    assert login_response.status_code == status.HTTP_204_NO_CONTENT
    authorize_response = await request_authorization_code(
        client,
        login_response=login_response,
        client_id="confidential-client",
        redirect_uri="https://confidential.example/callback",
    )

    response = await client.post(
        "/oauth2/token",
        data={
            "grant_type": "authorization_code",
            "code": authorization_code_from_redirect(authorize_response),
            "redirect_uri": "https://confidential.example/callback",
            "client_id": "confidential-client",
            "code_verifier": CODE_VERIFIER,
        },
    )

    assert response.status_code == status.HTTP_401_UNAUTHORIZED


@pytest.mark.asyncio
@pytest.mark.negative
async def test_authorization_code_exchange_rejects_wrong_redirect_uri(
    app: FastAPI,
    client: httpx.AsyncClient,
    verified_user_credentials: UserCredentials,
) -> None:
    """Assert code exchange binds the original redirect URI."""
    await create_public_authorization_code_client(app)
    login_response = await login_browser_session(client, verified_user_credentials)
    assert login_response.status_code == status.HTTP_204_NO_CONTENT
    authorize_response = await request_authorization_code(
        client, login_response=login_response
    )

    response = await client.post(
        "/oauth2/token",
        data={
            "grant_type": "authorization_code",
            "code": authorization_code_from_redirect(authorize_response),
            "redirect_uri": "https://client.example/wrong",
            "client_id": "public-client",
            "code_verifier": CODE_VERIFIER,
        },
    )

    assert response.status_code == status.HTTP_400_BAD_REQUEST


@pytest.mark.asyncio
@pytest.mark.negative
async def test_authorization_code_exchange_rejects_expired_code(
    app: FastAPI,
    client: httpx.AsyncClient,
    verified_user_credentials: UserCredentials,
) -> None:
    """Assert expired authorization codes cannot be exchanged."""
    await create_public_authorization_code_client(app)
    login_response = await login_browser_session(client, verified_user_credentials)
    assert login_response.status_code == status.HTTP_204_NO_CONTENT
    authorize_response = await request_authorization_code(
        client, login_response=login_response
    )
    async with app.state.core_session_factory() as db_session:
        await db_session.execute(
            update(OAuth2AuthorizationCodeDB).values(
                expires_at=datetime.now(UTC) - timedelta(seconds=1)
            )
        )
        await db_session.commit()

    response = await client.post(
        "/oauth2/token",
        data={
            "grant_type": "authorization_code",
            "code": authorization_code_from_redirect(authorize_response),
            "redirect_uri": "https://client.example/callback",
            "client_id": "public-client",
            "code_verifier": CODE_VERIFIER,
        },
    )

    assert response.status_code == status.HTTP_400_BAD_REQUEST


@pytest.mark.asyncio
@pytest.mark.negative
async def test_authorization_code_exchange_rejects_blocked_user(
    app: FastAPI,
    client: httpx.AsyncClient,
    verified_user_credentials: UserCredentials,
) -> None:
    """Assert authorization codes cannot be exchanged for blocked users."""
    await create_public_authorization_code_client(app)
    login_response = await login_browser_session(client, verified_user_credentials)
    assert login_response.status_code == status.HTTP_204_NO_CONTENT
    authorize_response = await request_authorization_code(
        client, login_response=login_response
    )
    async with app.state.core_session_factory() as db_session:
        await db_session.execute(
            update(UserDB)
            .where(
                UserDB.id == current_user_id_for_email(verified_user_credentials.email)
            )
            .values(is_active=False)
        )
        await db_session.commit()

    response = await client.post(
        "/oauth2/token",
        data={
            "grant_type": "authorization_code",
            "code": authorization_code_from_redirect(authorize_response),
            "redirect_uri": "https://client.example/callback",
            "client_id": "public-client",
            "code_verifier": CODE_VERIFIER,
        },
    )

    assert response.status_code == status.HTTP_400_BAD_REQUEST
    assert response.json()["error"] == "invalid_grant"


@pytest.mark.asyncio
@pytest.mark.negative
async def test_authorization_code_exchange_rejects_reuse(
    app: FastAPI,
    client: httpx.AsyncClient,
    verified_user_credentials: UserCredentials,
) -> None:
    """Assert an authorization code can only be exchanged once."""
    await create_public_authorization_code_client(app)
    login_response = await login_browser_session(client, verified_user_credentials)
    assert login_response.status_code == status.HTTP_204_NO_CONTENT
    authorize_response = await request_authorization_code(
        client, login_response=login_response
    )
    assert authorize_response.status_code == status.HTTP_302_FOUND
    raw_code = authorization_code_from_redirect(authorize_response)
    token_request = {
        "grant_type": "authorization_code",
        "code": raw_code,
        "redirect_uri": "https://client.example/callback",
        "client_id": "public-client",
        "code_verifier": CODE_VERIFIER,
    }

    first_response = await client.post("/oauth2/token", data=token_request)
    second_response = await client.post("/oauth2/token", data=token_request)

    assert first_response.status_code == status.HTTP_200_OK
    assert second_response.status_code == status.HTTP_400_BAD_REQUEST


@pytest.mark.asyncio
@pytest.mark.negative
async def test_authorization_code_exchange_rejects_bad_pkce_verifier(
    app: FastAPI,
    client: httpx.AsyncClient,
    verified_user_credentials: UserCredentials,
) -> None:
    """Assert code exchange rejects a mismatched PKCE verifier."""
    await create_public_authorization_code_client(app)
    login_response = await login_browser_session(client, verified_user_credentials)
    assert login_response.status_code == status.HTTP_204_NO_CONTENT
    authorize_response = await request_authorization_code(
        client, login_response=login_response
    )
    assert authorize_response.status_code == status.HTTP_302_FOUND

    response = await client.post(
        "/oauth2/token",
        data={
            "grant_type": "authorization_code",
            "code": authorization_code_from_redirect(authorize_response),
            "redirect_uri": "https://client.example/callback",
            "client_id": "public-client",
            "code_verifier": f"{CODE_VERIFIER}x",
        },
    )

    assert response.status_code == status.HTTP_400_BAD_REQUEST
