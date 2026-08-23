"""Black-box HTTP tests for browser authorization requests and consent."""

from unittest.mock import Mock
from urllib.parse import parse_qs, urlparse

import httpx
import pytest
from app.db.models.oauth2_authorization_code import (
    OAuth2AuthorizationCodeDB,
)
from app.db.models.oauth2_client import OAuth2ClientDB
from app.oauth2.authorization.code import create_s256_code_challenge
from app.oauth2.specs import OAuth2Specs
from fastapi import FastAPI, status
from sqlalchemy import select, update

from app.oauth2.authorization import request as authorization_request_workflow
from tests.fixtures.auth import UserCredentials
from tests.fixtures.oauth2 import (
    authorization_code_from_redirect,
    CODE_VERIFIER,
    create_public_authorization_code_client,
    login_browser_session,
    request_authorization_code,
    request_user_token,
    SHA256_HEX_LENGTH,
)


pytestmark = pytest.mark.api


@pytest.mark.asyncio
@pytest.mark.negative
async def test_authorize_rejects_oversized_protocol_state(
    client: httpx.AsyncClient,
) -> None:
    """Reject oversized state through the OAuth2 error boundary, not as 422."""
    response = await client.get(
        "/oauth2/authorize",
        params={
            "response_type": "code",
            "client_id": "public-client",
            "redirect_uri": "https://client.example/callback",
            "state": "x" * (OAuth2Specs.STATE_LENGTH_MAX + 1),
            "code_challenge": create_s256_code_challenge(code_verifier=CODE_VERIFIER),
            "code_challenge_method": "S256",
        },
    )

    assert response.status_code == status.HTTP_400_BAD_REQUEST
    assert response.json()["error"] == "invalid_request"


@pytest.mark.asyncio
@pytest.mark.system
async def test_authorize_issues_hashed_authorization_code(
    app: FastAPI,
    client: httpx.AsyncClient,
    verified_user_credentials: UserCredentials,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Assert authorize redirects with a raw code while storing only its hash."""
    await create_public_authorization_code_client(app)
    login_response = await login_browser_session(client, verified_user_credentials)
    assert login_response.status_code == status.HTTP_204_NO_CONTENT

    logger = Mock()
    monkeypatch.setattr(authorization_request_workflow, "logger", logger)
    response = await request_authorization_code(client, login_response=login_response)

    assert response.status_code == status.HTTP_302_FOUND
    raw_code = authorization_code_from_redirect(response)
    assert parse_qs(urlparse(response.headers["location"]).query)["state"] == [
        "state-value"
    ]
    async with app.state.core_session_factory() as db_session:
        stored_code = await db_session.scalar(
            select(OAuth2AuthorizationCodeDB.code_hash)
        )

    assert stored_code is not None
    assert stored_code != raw_code
    assert len(stored_code) == SHA256_HEX_LENGTH
    message = logger.info.call_args.args[0]
    assert "event=oauth2_authorization_code outcome=attempted" in message
    assert "event=oauth2_authorization_code outcome=issued" not in message


@pytest.mark.asyncio
@pytest.mark.negative
async def test_authorize_ignores_oauth2_bearer_and_starts_browser_login(
    app: FastAPI,
    client: httpx.AsyncClient,
    verified_user_credentials: UserCredentials,
) -> None:
    """Assert a bearer token cannot replace the browser login interaction."""
    await create_public_authorization_code_client(app)
    token_response = await request_user_token(app, client, verified_user_credentials)
    assert token_response.status_code == status.HTTP_200_OK
    client.cookies.clear()

    response = await client.get(
        "/oauth2/authorize",
        params={
            "response_type": "code",
            "client_id": "public-client",
            "redirect_uri": "https://client.example/callback",
            "scope": "read",
            "state": "state-value",
            "code_challenge": create_s256_code_challenge(code_verifier=CODE_VERIFIER),
            "code_challenge_method": "S256",
        },
        headers={"Authorization": f"Bearer {token_response.json()['access_token']}"},
        follow_redirects=False,
    )

    assert response.status_code == status.HTTP_303_SEE_OTHER
    assert urlparse(response.headers["location"]).path == "/login"


@pytest.mark.asyncio
async def test_authorize_requires_consent_when_client_is_configured(
    app: FastAPI,
    client: httpx.AsyncClient,
    verified_user_credentials: UserCredentials,
) -> None:
    """Assert consent-gated clients require approval before code issuance."""
    await create_public_authorization_code_client(app)
    async with app.state.core_session_factory() as db_session:
        await db_session.execute(
            update(OAuth2ClientDB)
            .where(OAuth2ClientDB.client_id == "public-client")
            .values(requires_consent=True)
        )
        await db_session.commit()
    login_response = await login_browser_session(client, verified_user_credentials)
    assert login_response.status_code == status.HTTP_204_NO_CONTENT

    consent_response = await request_authorization_code(
        client,
        login_response=login_response,
        consent=None,
    )
    deny_response = await request_authorization_code(
        client,
        login_response=login_response,
        consent="deny",
    )
    approve_response = await request_authorization_code(
        client,
        login_response=login_response,
        consent="approve",
    )

    assert consent_response.status_code == status.HTTP_200_OK
    assert "Allow Public Client?" in consent_response.text
    assert deny_response.status_code == status.HTTP_302_FOUND
    assert parse_qs(urlparse(deny_response.headers["location"]).query)["error"] == [
        "access_denied"
    ]
    assert approve_response.status_code == status.HTTP_302_FOUND
    assert authorization_code_from_redirect(approve_response)


@pytest.mark.asyncio
@pytest.mark.negative
async def test_authorize_rejects_redirect_uri_mismatch(
    app: FastAPI,
    client: httpx.AsyncClient,
    verified_user_credentials: UserCredentials,
) -> None:
    """Assert authorize rejects unregistered redirect URIs."""
    await create_public_authorization_code_client(app)
    login_response = await login_browser_session(client, verified_user_credentials)
    assert login_response.status_code == status.HTTP_204_NO_CONTENT

    response = await client.get(
        "/oauth2/authorize",
        params={
            "response_type": "code",
            "client_id": "public-client",
            "redirect_uri": "https://evil.example/callback",
            "code_challenge": create_s256_code_challenge(code_verifier=CODE_VERIFIER),
            "code_challenge_method": "S256",
        },
    )

    assert response.status_code == status.HTTP_400_BAD_REQUEST
    assert "location" not in response.headers


@pytest.mark.asyncio
async def test_authorize_redirects_invalid_scope_to_trusted_client(
    app: FastAPI,
    client: httpx.AsyncClient,
    verified_user_credentials: UserCredentials,
) -> None:
    """Assert scope errors redirect only after the client callback is trusted."""
    await create_public_authorization_code_client(app)
    login_response = await login_browser_session(client, verified_user_credentials)
    assert login_response.status_code == status.HTTP_204_NO_CONTENT

    response = await request_authorization_code(
        client,
        login_response=login_response,
        scope="write",
    )

    assert response.status_code == status.HTTP_302_FOUND
    query = parse_qs(urlparse(response.headers["location"]).query)
    assert query["error"] == ["invalid_scope"]
    assert query["state"] == ["state-value"]


@pytest.mark.asyncio
async def test_authorize_allows_global_client_for_user_from_another_organization(
    app: FastAPI,
    client: httpx.AsyncClient,
    verified_user_credentials: UserCredentials,
) -> None:
    """Assert a global client can be authorized regardless of user organization."""
    async with app.state.core_session_factory() as db_session:
        db_session.add(
            OAuth2ClientDB(
                client_id="other-organization-client",
                client_secret=None,
                name="Other Organization Client",
                grant_types=["authorization_code"],
                scopes=["read"],
                redirect_uris=["https://other-organization.example/callback"],
                is_confidential=False,
                requires_consent=True,
                is_active=True,
            )
        )
        await db_session.commit()
    login_response = await login_browser_session(client, verified_user_credentials)
    assert login_response.status_code == status.HTTP_204_NO_CONTENT

    response = await request_authorization_code(
        client,
        login_response=login_response,
        client_id="other-organization-client",
        redirect_uri="https://other-organization.example/callback",
    )

    assert response.status_code == status.HTTP_302_FOUND


@pytest.mark.asyncio
@pytest.mark.negative
async def test_authorize_rejects_missing_pkce(
    app: FastAPI,
    client: httpx.AsyncClient,
    verified_user_credentials: UserCredentials,
) -> None:
    """Assert authorization code flow requires PKCE."""
    await create_public_authorization_code_client(app)
    login_response = await login_browser_session(client, verified_user_credentials)
    assert login_response.status_code == status.HTTP_204_NO_CONTENT

    response = await client.get(
        "/oauth2/authorize",
        params={
            "response_type": "code",
            "client_id": "public-client",
            "redirect_uri": "https://client.example/callback",
        },
    )

    assert response.status_code == status.HTTP_400_BAD_REQUEST


@pytest.mark.asyncio
@pytest.mark.negative
async def test_authorize_rejects_unsupported_response_type(
    app: FastAPI,
    client: httpx.AsyncClient,
    verified_user_credentials: UserCredentials,
) -> None:
    """Assert authorize rejects non-code response types."""
    await create_public_authorization_code_client(app)
    login_response = await login_browser_session(client, verified_user_credentials)
    assert login_response.status_code == status.HTTP_204_NO_CONTENT

    response = await client.get(
        "/oauth2/authorize",
        params={
            "response_type": "token",
            "client_id": "public-client",
            "redirect_uri": "https://client.example/callback",
            "code_challenge": create_s256_code_challenge(code_verifier=CODE_VERIFIER),
            "code_challenge_method": "S256",
            "state": "opaque-state",
        },
        follow_redirects=False,
    )

    assert response.status_code == status.HTTP_302_FOUND
    query = parse_qs(urlparse(response.headers["location"]).query)
    assert query["error"] == ["unsupported_response_type"]
    assert query["state"] == ["opaque-state"]


@pytest.mark.asyncio
async def test_authorize_form_post_matches_get_semantics(
    app: FastAPI,
    client: httpx.AsyncClient,
    verified_user_credentials: UserCredentials,
) -> None:
    """Assert form-post authorization requests issue the same bound code."""
    await create_public_authorization_code_client(app)
    async with app.state.core_session_factory() as db_session:
        await db_session.execute(
            update(OAuth2ClientDB)
            .where(OAuth2ClientDB.client_id == "public-client")
            .values(requires_consent=False)
        )
        await db_session.commit()
    login_response = await login_browser_session(client, verified_user_credentials)
    assert login_response.status_code == status.HTTP_204_NO_CONTENT
    csrf_header_name = app.state.settings.session.csrf.header_name

    response = await client.post(
        "/oauth2/authorize",
        data={
            "response_type": "code",
            "client_id": "public-client",
            "redirect_uri": "https://client.example/callback",
            "scope": "read",
            "state": "form-post-state",
            "nonce": "form-post-nonce",
            "code_challenge": create_s256_code_challenge(code_verifier=CODE_VERIFIER),
            "code_challenge_method": "S256",
        },
        headers={
            "Origin": str(client.base_url).rstrip("/"),
            csrf_header_name: login_response.headers[csrf_header_name],
        },
        follow_redirects=False,
    )

    assert response.status_code == status.HTTP_302_FOUND
    query = parse_qs(urlparse(response.headers["location"]).query)
    assert query["state"] == ["form-post-state"]
    raw_code = query["code"][0]
    async with app.state.core_session_factory() as db_session:
        stored = await db_session.scalar(
            select(OAuth2AuthorizationCodeDB).where(
                OAuth2AuthorizationCodeDB.code_hash.is_not(None)
            )
        )
    assert stored is not None
    assert stored.nonce == "form-post-nonce"
    assert stored.code_hash != raw_code


@pytest.mark.asyncio
@pytest.mark.negative
async def test_authorize_rejects_inactive_client(
    app: FastAPI,
    client: httpx.AsyncClient,
    verified_user_credentials: UserCredentials,
) -> None:
    """Assert authorize rejects inactive clients."""
    await create_public_authorization_code_client(app)
    async with app.state.core_session_factory() as db_session:
        await db_session.execute(
            update(OAuth2ClientDB)
            .where(OAuth2ClientDB.client_id == "public-client")
            .values(is_active=False)
        )
        await db_session.commit()
    login_response = await login_browser_session(client, verified_user_credentials)
    assert login_response.status_code == status.HTTP_204_NO_CONTENT

    response = await request_authorization_code(
        client,
        login_response=login_response,
        consent=None,
    )

    assert response.status_code == status.HTTP_400_BAD_REQUEST
