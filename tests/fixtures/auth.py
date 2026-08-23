"""Reusable authentication helpers for tests."""

import re
from dataclasses import dataclass
from urllib.parse import parse_qs, urlparse

import httpx
from app.db.models.oauth2_client import OAuth2ClientDB
from app.db.models.user import UserDB, UserEmailDB
from app.identity.users.enums import UserEmailStatus
from app.oauth2.authorization.code import create_s256_code_challenge
from fastapi import FastAPI
from sqlalchemy import select
from sqlalchemy.sql.selectable import ScalarSelect


TEST_CODE_VERIFIER = (
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~"
)


def current_user_id_for_email(email: str) -> ScalarSelect[int]:
    """Return a scalar query resolving the current owner of an email."""
    return (
        select(UserEmailDB.user_id)
        .where(
            UserEmailDB.normalized_email == email.lower(),
            UserEmailDB.status == UserEmailStatus.CURRENT,
        )
        .scalar_subquery()
    )


@dataclass(frozen=True, slots=True)
class UserCredentials:
    """Credentials for a seeded test user."""

    email: str
    password: str


async def pre_session_csrf_headers(
    client: httpx.AsyncClient,
    *,
    header_name: str = "X-CSRF-Token",
    cookie_name: str = "csrftoken",
) -> dict[str, str]:
    """Initialize stateless login CSRF state and return request headers."""
    response = await client.get("/api/v1/sessions/csrf")
    assert response.is_success
    csrf_token = response.headers.get(header_name) or response.cookies[cookie_name]
    return {
        "Origin": str(client.base_url).rstrip("/"),
        header_name: csrf_token,
    }


async def login_browser(
    client: httpx.AsyncClient,
    credentials: UserCredentials,
    *,
    csrf_header_name: str = "X-CSRF-Token",
    csrf_cookie_name: str = "csrftoken",
) -> httpx.Response:
    """Log in through the pre-session CSRF-protected JSON endpoint."""
    headers = await pre_session_csrf_headers(
        client,
        header_name=csrf_header_name,
        cookie_name=csrf_cookie_name,
    )
    return await client.post(
        "/api/v1/sessions/login",
        json={"username": credentials.email, "password": credentials.password},
        headers=headers,
    )


async def issue_user_token(
    app: FastAPI,
    client: httpx.AsyncClient,
    credentials: UserCredentials,
    *,
    scope: str = "read",
) -> httpx.Response:
    """Issue a user token through Authorization Code with PKCE."""
    client_id = "test-user-client"
    redirect_uri = "https://test-client.example/callback"
    async with app.state.core_session_factory() as session:
        user = await session.scalar(
            select(UserDB)
            .join(UserEmailDB, UserEmailDB.user_id == UserDB.id)
            .where(UserEmailDB.normalized_email == credentials.email.lower())
        )
        assert user is not None
        oauth2_client = await session.scalar(
            select(OAuth2ClientDB).where(OAuth2ClientDB.client_id == client_id)
        )
        if oauth2_client is None:
            session.add(
                OAuth2ClientDB(
                    client_id=client_id,
                    client_secret=None,
                    name="Test User Client",
                    grant_types=["authorization_code", "refresh_token"],
                    scopes=[scope],
                    redirect_uris=[redirect_uri],
                    is_confidential=False,
                    requires_consent=True,
                    is_active=True,
                )
            )
            await session.commit()

    return await request_seeded_user_token(client, credentials, scope=scope)


async def request_seeded_user_token(
    client: httpx.AsyncClient,
    credentials: UserCredentials,
    *,
    scope: str = "read",
) -> httpx.Response:
    """Issue a token for a user whose OAuth2 test client is already seeded."""
    client_id = "test-user-client"
    redirect_uri = "https://test-client.example/callback"
    await login_browser(client, credentials)
    authorize_response = await client.get(
        "/oauth2/authorize",
        params={
            "response_type": "code",
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "scope": scope,
            "state": "test-state",
            "code_challenge": create_s256_code_challenge(
                code_verifier=TEST_CODE_VERIFIER
            ),
            "code_challenge_method": "S256",
        },
        follow_redirects=False,
    )
    if (
        authorize_response.is_redirect
        and urlparse(authorize_response.headers["location"]).path == "/consent"
    ):
        authorize_response = await client.get(
            authorize_response.headers["location"],
            follow_redirects=False,
        )
    if not authorize_response.is_redirect:
        transaction_match = re.search(
            r'name="transaction_id" value="([^"]+)"',
            authorize_response.text,
        )
        if transaction_match is None:
            msg = "Authorization consent response did not contain a transaction_id."
            raise AssertionError(msg)
        csrf_response = await client.get("/api/v1/sessions/csrf")
        csrf_header_name = next(
            header_name
            for header_name in csrf_response.headers
            if header_name.lower().startswith("x-csrf")
        )
        authorize_response = await client.post(
            "/oauth2/authorize/decision",
            data={
                "transaction_id": transaction_match.group(1),
                "decision": "approve",
            },
            headers={
                "Origin": str(client.base_url).rstrip("/"),
                csrf_header_name: csrf_response.headers[csrf_header_name],
            },
            follow_redirects=False,
        )
    assert authorize_response.is_redirect, (
        f"Authorization approval failed: {authorize_response.status_code} "
        f"{authorize_response.text}"
    )
    code = parse_qs(urlparse(authorize_response.headers["location"]).query)["code"][0]
    return await client.post(
        "/oauth2/token",
        data={
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": redirect_uri,
            "client_id": client_id,
            "code_verifier": TEST_CODE_VERIFIER,
        },
    )
