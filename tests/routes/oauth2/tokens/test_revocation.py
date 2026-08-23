"""Black-box HTTP tests for OAuth2 token revocation and ownership rules."""

import httpx
import pytest
from app.db.models.oauth2_session import OAuth2SessionDB
from fastapi import FastAPI, status
from sqlalchemy import select

from tests.fixtures.auth import UserCredentials
from tests.fixtures.oauth2 import (
    add_oauth2_required_context_route,
    authorization_code_from_redirect,
    CODE_VERIFIER,
    count_token_pairs,
    create_other_public_client,
    create_public_authorization_code_client,
    login_browser_session,
    request_authorization_code,
)


pytestmark = pytest.mark.api


@pytest.mark.asyncio
@pytest.mark.system
async def test_revoke_access_token_deletes_client_owned_token_pair(
    app: FastAPI,
    client: httpx.AsyncClient,
    verified_user_credentials: UserCredentials,
) -> None:
    """Assert a public client can revoke its own access token."""
    add_oauth2_required_context_route(app)
    await create_public_authorization_code_client(app)
    login_response = await login_browser_session(client, verified_user_credentials)
    assert login_response.status_code == status.HTTP_204_NO_CONTENT
    authorize_response = await request_authorization_code(
        client, login_response=login_response
    )
    token_response = await client.post(
        "/oauth2/token",
        data={
            "grant_type": "authorization_code",
            "code": authorization_code_from_redirect(authorize_response),
            "redirect_uri": "https://client.example/callback",
            "client_id": "public-client",
            "code_verifier": CODE_VERIFIER,
        },
    )
    access_token = token_response.json()["access_token"]

    revoke_response = await client.post(
        "/oauth2/revoke",
        data={
            "token": access_token,
            "token_type_hint": "access_token",
            "client_id": "public-client",
        },
    )
    protected_response = await client.get(
        "/test/oauth2/required-context",
        headers={"Authorization": f"Bearer {access_token}"},
    )
    async with app.state.core_session_factory() as db_session:
        session_ended_at = await db_session.scalar(select(OAuth2SessionDB.ended_at))

    assert revoke_response.status_code == status.HTTP_200_OK
    assert protected_response.status_code == status.HTTP_401_UNAUTHORIZED
    assert session_ended_at is not None
    assert await count_token_pairs(app) == 0


@pytest.mark.asyncio
async def test_revoke_treats_token_type_hint_as_advisory(
    app: FastAPI,
    client: httpx.AsyncClient,
    verified_user_credentials: UserCredentials,
) -> None:
    """Assert revocation still deletes a token when the hint is wrong."""
    await create_public_authorization_code_client(app)
    login_response = await login_browser_session(client, verified_user_credentials)
    assert login_response.status_code == status.HTTP_204_NO_CONTENT
    authorize_response = await request_authorization_code(
        client, login_response=login_response
    )
    token_response = await client.post(
        "/oauth2/token",
        data={
            "grant_type": "authorization_code",
            "code": authorization_code_from_redirect(authorize_response),
            "redirect_uri": "https://client.example/callback",
            "client_id": "public-client",
            "code_verifier": CODE_VERIFIER,
        },
    )
    refresh_token = token_response.json()["refresh_token"]

    revoke_response = await client.post(
        "/oauth2/revoke",
        data={
            "token": refresh_token,
            "token_type_hint": "access_token",
            "client_id": "public-client",
        },
    )

    assert revoke_response.status_code == status.HTTP_200_OK
    assert revoke_response.headers["Cache-Control"] == "no-store"
    assert revoke_response.headers["Pragma"] == "no-cache"
    assert await count_token_pairs(app) == 0


@pytest.mark.asyncio
@pytest.mark.system
async def test_revoke_refresh_token_hint_deletes_client_owned_pair(
    app: FastAPI,
    client: httpx.AsyncClient,
    verified_user_credentials: UserCredentials,
) -> None:
    """Assert refresh-token revocation hint deletes client-owned token pairs."""
    await create_public_authorization_code_client(app)
    login_response = await login_browser_session(client, verified_user_credentials)
    assert login_response.status_code == status.HTTP_204_NO_CONTENT
    authorize_response = await request_authorization_code(
        client, login_response=login_response
    )
    token_response = await client.post(
        "/oauth2/token",
        data={
            "grant_type": "authorization_code",
            "code": authorization_code_from_redirect(authorize_response),
            "redirect_uri": "https://client.example/callback",
            "client_id": "public-client",
            "code_verifier": CODE_VERIFIER,
        },
    )
    assert token_response.status_code == status.HTTP_200_OK
    refresh_token = token_response.json()["refresh_token"]

    revoke_response = await client.post(
        "/oauth2/revoke",
        data={
            "token": refresh_token,
            "token_type_hint": "refresh_token",
            "client_id": "public-client",
        },
    )

    assert revoke_response.status_code == status.HTTP_200_OK
    assert await count_token_pairs(app) == 0


@pytest.mark.asyncio
@pytest.mark.negative
async def test_revoke_ignores_token_owned_by_another_client(
    app: FastAPI,
    client: httpx.AsyncClient,
    verified_user_credentials: UserCredentials,
) -> None:
    """Assert one public client cannot revoke another client's token."""
    add_oauth2_required_context_route(app)
    await create_public_authorization_code_client(app)
    await create_other_public_client(app)
    login_response = await login_browser_session(client, verified_user_credentials)
    assert login_response.status_code == status.HTTP_204_NO_CONTENT
    authorize_response = await request_authorization_code(
        client, login_response=login_response
    )
    token_response = await client.post(
        "/oauth2/token",
        data={
            "grant_type": "authorization_code",
            "code": authorization_code_from_redirect(authorize_response),
            "redirect_uri": "https://client.example/callback",
            "client_id": "public-client",
            "code_verifier": CODE_VERIFIER,
        },
    )
    access_token = token_response.json()["access_token"]

    revoke_response = await client.post(
        "/oauth2/revoke",
        data={
            "token": access_token,
            "token_type_hint": "access_token",
            "client_id": "other-public-client",
        },
    )
    protected_response = await client.get(
        "/test/oauth2/required-context",
        headers={"Authorization": f"Bearer {access_token}"},
    )

    assert revoke_response.status_code == status.HTTP_200_OK
    assert protected_response.status_code == status.HTTP_200_OK
    assert await count_token_pairs(app) == 1
