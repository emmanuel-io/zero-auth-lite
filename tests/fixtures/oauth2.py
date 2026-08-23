# ruff: noqa: PLR0913
"""Shared setup for OAuth2 lifecycle integration tests."""

import base64
import json
import re
from datetime import datetime, UTC
from typing import Annotated, cast
from urllib.parse import parse_qs, urlparse

import httpx
from app.db.models.oauth2_client import OAuth2ClientDB
from app.db.models.oauth2_token_pair import OAuth2TokenPairDB
from app.db.models.organization import OrganizationDB
from app.db.models.organization_membership import OrganizationMembershipDB
from app.db.models.user import UserDB, UserEmailDB
from app.identity.users.enums import UserEmailStatus
from app.oauth2.authorization.code import create_s256_code_challenge
from app.password.pwdlib_hasher import PwdlibPasswordHasher
from app.security.authentication import (
    CurrentUserContextDep,
    OAuth2PrincipalContextDep,
)
from app.security.authorization import require_oauth2_scopes
from app.security.dtos import OAuth2PrincipalContext
from fastapi import Depends, FastAPI
from sqlalchemy import func, insert, select

from tests.fixtures.auth import issue_user_token, login_browser, UserCredentials


BEARER_TOKEN_TYPE = "bearer"  # noqa: S105
CODE_VERIFIER = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~"
SHA256_HEX_LENGTH = 64
PASSWORD_HASHER = PwdlibPasswordHasher()


async def create_oauth2_test_identity(app: FastAPI) -> tuple[int, int]:
    """Create an organization and user that can own OAuth2 persistence rows."""
    async with app.state.core_session_factory() as db_session:
        organization = (
            await db_session.execute(
                insert(OrganizationDB)
                .values(name="OAuth2 Store Organization")
                .returning(OrganizationDB)
            )
        ).scalar_one()
        user = (
            await db_session.execute(
                insert(UserDB)
                .values(
                    hashed_password="not-used-by-store-tests",  # noqa: S106
                    is_active=True,
                )
                .returning(UserDB)
            )
        ).scalar_one()
        db_session.add(
            UserEmailDB(
                user_id=user.id,
                email="oauth2-store-user@example.com",
                normalized_email="oauth2-store-user@example.com",
                status=UserEmailStatus.CURRENT,
                verified_at=datetime.now(UTC),
            )
        )
        db_session.add(
            OrganizationMembershipDB(
                user_id=user.id,
                organization_id=organization.id,
            )
        )
        await db_session.commit()
    return organization.id, user.id


async def create_oauth2_test_client(
    app: FastAPI,
    *,
    client_id: str = "client",
) -> None:
    """Create the registered client referenced by OAuth2 persistence tests."""
    async with app.state.core_session_factory() as db_session:
        db_session.add(
            OAuth2ClientDB(
                client_id=client_id,
                client_secret=None,
                name="OAuth2 Store Client",
                grant_types=["authorization_code", "refresh_token"],
                scopes=["read", "write"],
                redirect_uris=["https://client.example/callback"],
                is_confidential=False,
                requires_consent=True,
                is_active=True,
            )
        )
        await db_session.commit()


async def request_user_token(
    app: FastAPI,
    client: httpx.AsyncClient,
    credentials: UserCredentials,
) -> httpx.Response:
    """Issue a user token through Authorization Code with PKCE."""
    return await issue_user_token(app, client, credentials)


def add_oauth2_required_context_route(app: FastAPI) -> None:
    """Add a test route that requires OAuth2 bearer authentication."""

    @app.get(
        "/test/oauth2/required-context",
        dependencies=[],
    )
    async def required_context_route(
        _user_ctx: CurrentUserContextDep,
    ) -> dict[str, bool]:
        """Return whether required auth resolved a user context."""
        return {"authenticated": True}


def add_oauth2_principal_routes(app: FastAPI) -> None:
    """Add test routes that require OAuth2 bearer principal authentication."""

    @app.get(
        "/test/oauth2/required-principal",
        dependencies=[],
    )
    async def required_principal_route(
        principal_ctx: OAuth2PrincipalContextDep,
    ) -> dict[str, object]:
        """Return the resolved principal shape."""
        return {
            "client_id": principal_ctx.client_id,
            "user_id": getattr(principal_ctx, "user_id", None),
            "organization_id": principal_ctx.organization_id,
            "scopes": sorted(principal_ctx.scopes),
        }

    @app.get(
        "/test/oauth2/scoped-principal",
        dependencies=[],
    )
    async def scoped_principal_route(
        principal_ctx: Annotated[
            OAuth2PrincipalContext,
            Depends(require_oauth2_scopes("service:read")),
        ],
    ) -> dict[str, object]:
        """Return the resolved principal after scope enforcement."""
        return {
            "client_id": principal_ctx.client_id,
            "scopes": sorted(principal_ctx.scopes),
        }

    @app.get(
        "/test/oauth2/write-scoped-principal",
        dependencies=[],
    )
    async def write_scoped_principal_route(
        principal_ctx: Annotated[
            OAuth2PrincipalContext,
            Depends(require_oauth2_scopes("service:write")),
        ],
    ) -> dict[str, object]:
        """Return the resolved principal after write-scope enforcement."""
        return {
            "client_id": principal_ctx.client_id,
            "scopes": sorted(principal_ctx.scopes),
        }


async def count_token_pairs(app: FastAPI) -> int:
    """Count persisted OAuth2 token pairs."""
    async with app.state.core_session_factory() as db_session:
        return int(
            await db_session.scalar(select(func.count()).select_from(OAuth2TokenPairDB))
            or 0
        )


async def create_public_authorization_code_client(app: FastAPI) -> None:
    """Create a public OAuth2 client that can use authorization code + PKCE."""
    async with app.state.core_session_factory() as db_session:
        db_session.add(
            OAuth2ClientDB(
                client_id="public-client",
                client_secret=None,
                name="Public Client",
                grant_types=["authorization_code", "refresh_token"],
                scopes=["read"],
                redirect_uris=["https://client.example/callback"],
                is_confidential=False,
                requires_consent=True,
                is_active=True,
            )
        )
        await db_session.commit()


async def create_public_oidc_client(app: FastAPI) -> None:
    """Create a public OIDC client that can request openid scopes."""
    async with app.state.core_session_factory() as db_session:
        db_session.add(
            OAuth2ClientDB(
                client_id="oidc-client",
                client_secret=None,
                name="OIDC Client",
                grant_types=["authorization_code", "refresh_token"],
                scopes=["openid", "email", "profile"],
                redirect_uris=["https://oidc.example/callback"],
                is_confidential=False,
                requires_consent=True,
                is_active=True,
            )
        )
        await db_session.commit()


async def create_confidential_authorization_code_client(app: FastAPI) -> str:
    """Create a confidential OAuth2 client and return its raw secret."""
    raw_secret = "confidential-client-secret"  # noqa: S105
    async with app.state.core_session_factory() as db_session:
        db_session.add(
            OAuth2ClientDB(
                client_id="confidential-client",
                client_secret=PASSWORD_HASHER.hash(raw_secret),
                name="Confidential Client",
                grant_types=["authorization_code", "refresh_token"],
                scopes=["read"],
                redirect_uris=["https://confidential.example/callback"],
                is_confidential=True,
                is_active=True,
            )
        )
        await db_session.commit()
    return raw_secret


async def create_other_public_client(app: FastAPI) -> None:
    """Create another public OAuth2 client for ownership tests."""
    async with app.state.core_session_factory() as db_session:
        db_session.add(
            OAuth2ClientDB(
                client_id="other-public-client",
                client_secret=None,
                name="Other Public Client",
                grant_types=["authorization_code", "refresh_token"],
                scopes=["read"],
                redirect_uris=["https://other.example/callback"],
                is_confidential=False,
                requires_consent=True,
                is_active=True,
            )
        )
        await db_session.commit()


async def create_confidential_machine_client(app: FastAPI) -> str:
    """Create a confidential client-credentials client and return its secret."""
    raw_secret = "machine-client-secret"  # noqa: S105
    async with app.state.core_session_factory() as db_session:
        db_session.add(
            OAuth2ClientDB(
                client_id="machine-client",
                client_secret=PASSWORD_HASHER.hash(raw_secret),
                name="Machine Client",
                grant_types=["client_credentials"],
                scopes=["service:read"],
                redirect_uris=[],
                is_confidential=True,
                is_active=True,
            )
        )
        await db_session.commit()
    return raw_secret


async def create_public_client_credentials_client(app: FastAPI) -> None:
    """Create a public client registered for client credentials."""
    async with app.state.core_session_factory() as db_session:
        db_session.add(
            OAuth2ClientDB(
                client_id="public-machine-client",
                client_secret=None,
                name="Public Machine Client",
                grant_types=["client_credentials"],
                scopes=["service:read"],
                redirect_uris=[],
                is_confidential=False,
                is_active=True,
            )
        )
        await db_session.commit()


async def login_browser_session(
    client: httpx.AsyncClient,
    credentials: UserCredentials,
) -> httpx.Response:
    """Log in through browser session auth for authorize endpoint tests."""
    return await login_browser(client, credentials)


async def request_authorization_code(
    client: httpx.AsyncClient,
    *,
    login_response: httpx.Response | None = None,
    client_id: str = "public-client",
    redirect_uri: str = "https://client.example/callback",
    scope: str = "read",
    consent: str | None = "approve",
) -> httpx.Response:
    """Request an authorization code from the authorize endpoint."""
    params = {
        "response_type": "code",
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "scope": scope,
        "state": "state-value",
        "code_challenge": create_s256_code_challenge(code_verifier=CODE_VERIFIER),
        "code_challenge_method": "S256",
    }
    response = await client.get(
        "/oauth2/authorize",
        params=params,
        follow_redirects=False,
    )
    if (
        response.is_redirect
        and urlparse(response.headers["location"]).path == "/consent"
    ):
        response = await client.get(
            response.headers["location"],
            follow_redirects=False,
        )
    if consent is None or response.is_redirect:
        return response

    if login_response is None:
        msg = "login_response is required for POST-based consent submission."
        raise AssertionError(msg)
    csrf_header_name = next(
        header_name
        for header_name in login_response.headers
        if header_name.lower().startswith("x-csrf")
    )
    transaction_match = re.search(
        r'name="transaction_id" value="([^"]+)"',
        response.text,
    )
    if transaction_match is None:
        msg = "Authorization consent response did not contain a transaction_id."
        raise AssertionError(msg)
    return await client.post(
        "/oauth2/authorize/decision",
        data={
            "transaction_id": transaction_match.group(1),
            "decision": consent,
        },
        headers={
            "Origin": str(client.base_url).rstrip("/"),
            csrf_header_name: login_response.headers[csrf_header_name],
        },
        follow_redirects=False,
    )


def authorization_code_from_redirect(response: httpx.Response) -> str:
    """Extract an authorization code from an authorize redirect response."""
    parsed_query = parse_qs(urlparse(response.headers["location"]).query)
    return parsed_query["code"][0]


def decode_unverified_jwt_payload(token: str) -> dict[str, object]:
    """Decode JWT payload without verifying the signature for claim-shape tests."""
    _header, payload, _signature = token.split(".")
    padded_payload = payload + "=" * (-len(payload) % 4)
    return cast(
        "dict[str, object]", json.loads(base64.urlsafe_b64decode(padded_payload))
    )
