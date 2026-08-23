"""Black-box HTTP tests for refresh tokens and bearer-token authentication."""

import asyncio
import re
from datetime import datetime, timedelta, UTC
from unittest.mock import Mock

import httpx
import pytest
from app.db.models.oauth2_client import OAuth2ClientDB
from app.db.models.oauth2_session import OAuth2SessionDB
from app.db.models.oauth2_token_pair import OAuth2TokenPairDB
from app.db.models.user import UserDB, UserEmailDB
from app.identity.users.enums import UserEmailStatus
from app.oauth2.settings import OAuth2Settings
from app.oauth2.tokens.dtos import TokenPairUpdateDTO
from app.public_ids import PUBLIC_ID_PAYLOAD_PATTERN
from fastapi import FastAPI, status
from sqlalchemy import func, select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.oauth2.tokens import refresh as refresh_workflow
from tests.fixtures.auth import current_user_id_for_email, UserCredentials
from tests.fixtures.oauth2 import (
    add_oauth2_required_context_route,
    authorization_code_from_redirect,
    CODE_VERIFIER,
    count_token_pairs,
    create_other_public_client,
    create_public_authorization_code_client,
    decode_unverified_jwt_payload,
    login_browser_session,
    request_authorization_code,
    request_user_token,
    SHA256_HEX_LENGTH,
)


pytestmark = pytest.mark.api


@pytest.mark.asyncio
@pytest.mark.negative
async def test_bearer_auth_rejects_malformed_encoded_header(
    app: FastAPI,
    client: httpx.AsyncClient,
) -> None:
    """Translate a malformed JWT header into the safe bearer error response."""
    add_oauth2_required_context_route(app)

    response = await client.get(
        "/test/oauth2/required-context",
        headers={"Authorization": "Bearer ____.payload.signature"},
    )

    assert response.status_code == status.HTTP_401_UNAUTHORIZED
    assert response.headers["WWW-Authenticate"] == "Bearer"


@pytest.mark.asyncio
@pytest.mark.negative
async def test_token_endpoint_rejects_unsupported_grant_type(
    client: httpx.AsyncClient,
) -> None:
    """Assert unsupported grant types are rejected during request parsing."""
    response = await client.post(
        "/oauth2/token",
        data={
            "grant_type": "implicit",
        },
    )

    assert response.status_code == status.HTTP_400_BAD_REQUEST
    assert response.json()["error"] == "unsupported_grant_type"


@pytest.mark.asyncio
async def test_token_store_hashes_access_and_refresh_tokens(
    app: FastAPI,
    client: httpx.AsyncClient,
    verified_user_credentials: UserCredentials,
) -> None:
    """Assert persisted token lookup values are HMACs, not raw tokens."""
    response = await request_user_token(app, client, verified_user_credentials)
    assert response.status_code == status.HTTP_200_OK
    body = response.json()

    async with app.state.core_session_factory() as db_session:
        token_pair = await db_session.scalar(select(OAuth2TokenPairDB))
        oauth2_session = await db_session.scalar(select(OAuth2SessionDB))

    assert token_pair is not None
    assert token_pair.access_token_hash != body["access_token"]
    assert token_pair.refresh_token_hash != body["refresh_token"]
    assert len(token_pair.access_token_hash) == SHA256_HEX_LENGTH
    assert len(token_pair.refresh_token_hash) == SHA256_HEX_LENGTH
    assert oauth2_session is not None
    assert oauth2_session.grant_type == "authorization_code"


@pytest.mark.asyncio
async def test_access_token_uses_public_jwt_claims(
    app: FastAPI,
    client: httpx.AsyncClient,
    verified_user_credentials: UserCredentials,
) -> None:
    """Assert JWT access tokens expose public identifiers but not internal IDs."""
    response = await request_user_token(app, client, verified_user_credentials)
    assert response.status_code == status.HTTP_200_OK

    claims = decode_unverified_jwt_payload(response.json()["access_token"])

    assert isinstance(claims["sub"], str)
    assert re.fullmatch(rf"usr_{PUBLIC_ID_PAYLOAD_PATTERN}", claims["sub"])
    assert isinstance(claims["organization"], str)
    assert re.fullmatch(rf"org_{PUBLIC_ID_PAYLOAD_PATTERN}", claims["organization"])
    assert claims["aud"] == app.state.settings.oauth2.jwt_audience
    assert claims["iss"] == app.state.settings.oauth2.jwt_issuer
    assert claims["scope"] == "read"
    assert "jti" in claims
    assert "email" not in claims
    assert "sid" not in claims


@pytest.mark.asyncio
@pytest.mark.system
async def test_refresh_token_rotates_persisted_token_pair(
    app: FastAPI,
    client: httpx.AsyncClient,
    verified_user_credentials: UserCredentials,
) -> None:
    """Assert refresh grant returns newly rotated access and refresh tokens."""
    login_response = await request_user_token(app, client, verified_user_credentials)
    assert login_response.status_code == status.HTTP_200_OK
    original_pair = login_response.json()
    async with app.state.core_session_factory() as db_session:
        original_deadline = await db_session.scalar(
            select(OAuth2TokenPairDB.refresh_expires_at)
        )

    refresh_response = await client.post(
        "/oauth2/token",
        data={
            "grant_type": "refresh_token",
            "refresh_token": original_pair["refresh_token"],
            "client_id": "test-user-client",
        },
    )

    assert refresh_response.status_code == status.HTTP_200_OK
    refreshed_pair = refresh_response.json()
    assert refreshed_pair["access_token"] != original_pair["access_token"]
    assert refreshed_pair["refresh_token"] != original_pair["refresh_token"]
    async with app.state.core_session_factory() as db_session:
        rotated_deadline = await db_session.scalar(
            select(OAuth2TokenPairDB.refresh_expires_at)
        )
    assert rotated_deadline == original_deadline


@pytest.mark.asyncio
@pytest.mark.negative
async def test_refresh_token_does_not_mask_internal_value_error(
    app: FastAPI,
    client: httpx.AsyncClient,
    verified_user_credentials: UserCredentials,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Let unexpected token construction defects escape OAuth2 error mapping."""
    login_response = await request_user_token(app, client, verified_user_credentials)
    refresh_token = login_response.json()["refresh_token"]

    def fail_rotation(*_args: object, **_kwargs: object) -> None:
        msg = "unexpected rotation defect"
        raise ValueError(msg)

    monkeypatch.setattr(
        refresh_workflow.TokenIssuanceService,
        "create_rotation_tokens",
        fail_rotation,
    )

    with pytest.raises(ValueError, match="unexpected rotation defect"):
        await client.post(
            "/oauth2/token",
            data={
                "grant_type": "refresh_token",
                "refresh_token": refresh_token,
                "client_id": "test-user-client",
            },
        )


@pytest.mark.asyncio
@pytest.mark.negative
async def test_refresh_token_for_client_bound_pair_requires_client_authentication(
    app: FastAPI,
    client: httpx.AsyncClient,
    verified_user_credentials: UserCredentials,
) -> None:
    """Assert client-bound refresh tokens cannot rotate without the client."""
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

    missing_client_response = await client.post(
        "/oauth2/token",
        data={
            "grant_type": "refresh_token",
            "refresh_token": refresh_token,
        },
    )
    authenticated_client_response = await client.post(
        "/oauth2/token",
        data={
            "grant_type": "refresh_token",
            "refresh_token": refresh_token,
            "client_id": "public-client",
        },
    )

    assert missing_client_response.status_code == status.HTTP_400_BAD_REQUEST
    assert authenticated_client_response.status_code == status.HTTP_200_OK


@pytest.mark.asyncio
@pytest.mark.negative
async def test_refresh_token_rejects_reused_rotated_token(
    app: FastAPI,
    client: httpx.AsyncClient,
    verified_user_credentials: UserCredentials,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Assert a rotated refresh token cannot be reused."""
    login_response = await request_user_token(app, client, verified_user_credentials)
    assert login_response.status_code == status.HTTP_200_OK
    original_refresh_token = login_response.json()["refresh_token"]

    refresh_response = await client.post(
        "/oauth2/token",
        data={
            "grant_type": "refresh_token",
            "refresh_token": original_refresh_token,
            "client_id": "test-user-client",
        },
    )
    assert refresh_response.status_code == status.HTTP_200_OK

    logger = Mock()
    monkeypatch.setattr(refresh_workflow, "logger", logger)
    reused_response = await client.post(
        "/oauth2/token",
        data={
            "grant_type": "refresh_token",
            "refresh_token": original_refresh_token,
            "client_id": "test-user-client",
        },
    )

    assert reused_response.status_code == status.HTTP_400_BAD_REQUEST
    assert reused_response.json()["error"] == "invalid_grant"
    async with app.state.core_session_factory() as db_session:
        token_count = await db_session.scalar(
            select(func.count()).select_from(OAuth2TokenPairDB)
        )
        ended_at = await db_session.scalar(select(OAuth2SessionDB.ended_at))

    assert token_count == 0
    assert ended_at is not None
    assert (
        "event=oauth2_refresh_reuse outcome=revoked"
        in (logger.warning.call_args.args[0])
    )


@pytest.mark.asyncio
@pytest.mark.system
async def test_refresh_cas_loser_does_not_revoke_successful_rotation(
    app: FastAPI,
    client: httpx.AsyncClient,
    verified_user_credentials: UserCredentials,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Assert a compare-and-swap loser does not revoke the winning token pair."""
    login_response = await request_user_token(app, client, verified_user_credentials)
    assert login_response.status_code == status.HTTP_200_OK
    original_refresh_token = login_response.json()["refresh_token"]

    original_update = refresh_workflow.rotate_token_pair
    concurrent_request_count = 2
    update_arrivals = 0

    async def coordinated_update(
        *,
        db_session: AsyncSession,
        settings: OAuth2Settings,
        session_id: int,
        current_refresh_hash: str,
        data: TokenPairUpdateDTO,
    ) -> bool:
        nonlocal update_arrivals
        update_arrivals += 1
        if update_arrivals == concurrent_request_count:
            return False
        return await original_update(
            db_session=db_session,
            settings=settings,
            session_id=session_id,
            data=data,
            current_refresh_hash=current_refresh_hash,
        )

    monkeypatch.setattr(refresh_workflow, "rotate_token_pair", coordinated_update)
    request_data = {
        "grant_type": "refresh_token",
        "refresh_token": original_refresh_token,
        "client_id": "test-user-client",
    }

    responses = await asyncio.gather(
        client.post("/oauth2/token", data=request_data),
        client.post("/oauth2/token", data=request_data),
    )

    successful_response = next(
        response for response in responses if response.status_code == status.HTTP_200_OK
    )
    assert sorted(response.status_code for response in responses) == [
        status.HTTP_200_OK,
        status.HTTP_400_BAD_REQUEST,
    ]

    next_refresh_response = await client.post(
        "/oauth2/token",
        data={
            "grant_type": "refresh_token",
            "refresh_token": successful_response.json()["refresh_token"],
            "client_id": "test-user-client",
        },
    )

    assert next_refresh_response.status_code == status.HTTP_200_OK


@pytest.mark.asyncio
@pytest.mark.negative
async def test_refresh_token_rejects_expired_refresh_token(
    app: FastAPI,
    client: httpx.AsyncClient,
    verified_user_credentials: UserCredentials,
) -> None:
    """Assert expired refresh tokens are rejected and deleted."""
    login_response = await request_user_token(app, client, verified_user_credentials)
    assert login_response.status_code == status.HTTP_200_OK
    refresh_token = login_response.json()["refresh_token"]

    async with app.state.core_session_factory() as db_session:
        await db_session.execute(
            update(OAuth2TokenPairDB).values(
                refresh_expires_at=datetime.now(UTC) - timedelta(seconds=1)
            )
        )
        await db_session.commit()

    response = await client.post(
        "/oauth2/token",
        data={
            "grant_type": "refresh_token",
            "refresh_token": refresh_token,
            "client_id": "test-user-client",
        },
    )

    assert response.status_code == status.HTTP_400_BAD_REQUEST
    assert response.json()["error"] == "invalid_grant"
    assert await count_token_pairs(app) == 0
    async with app.state.core_session_factory() as db_session:
        ended_at = await db_session.scalar(select(OAuth2SessionDB.ended_at))
    assert ended_at is not None


@pytest.mark.asyncio
@pytest.mark.negative
async def test_refresh_token_state_rejects_missing_refresh_expiry(
    app: FastAPI,
    client: httpx.AsyncClient,
    verified_user_credentials: UserCredentials,
) -> None:
    """Assert persisted refresh tokens must carry an expiration timestamp."""
    login_response = await request_user_token(app, client, verified_user_credentials)
    assert login_response.status_code == status.HTTP_200_OK
    async with app.state.core_session_factory() as db_session:
        with pytest.raises(IntegrityError, match="refresh_pair"):
            await db_session.execute(
                update(OAuth2TokenPairDB).values(refresh_expires_at=None)
            )
        await db_session.rollback()

    assert await count_token_pairs(app) == 1


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("is_active", "email_verified"),
    [
        pytest.param(False, True, id="inactive"),
        pytest.param(True, False, id="unverified"),
    ],
)
@pytest.mark.negative
async def test_refresh_token_rejects_blocked_user(
    app: FastAPI,
    client: httpx.AsyncClient,
    verified_user_credentials: UserCredentials,
    is_active: bool,  # noqa: FBT001
    email_verified: bool,  # noqa: FBT001
) -> None:
    """Assert refresh grant rejects users that became blocked."""
    login_response = await request_user_token(app, client, verified_user_credentials)
    assert login_response.status_code == status.HTTP_200_OK
    refresh_token = login_response.json()["refresh_token"]
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

    response = await client.post(
        "/oauth2/token",
        data={
            "grant_type": "refresh_token",
            "refresh_token": refresh_token,
            "client_id": "test-user-client",
        },
    )

    assert response.status_code == status.HTTP_400_BAD_REQUEST
    assert response.json()["error"] == "invalid_grant"


@pytest.mark.asyncio
@pytest.mark.negative
async def test_refresh_token_rejects_wrong_client(
    app: FastAPI,
    client: httpx.AsyncClient,
    verified_user_credentials: UserCredentials,
) -> None:
    """Assert client-bound refresh tokens cannot rotate for another client."""
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

    response = await client.post(
        "/oauth2/token",
        data={
            "grant_type": "refresh_token",
            "refresh_token": token_response.json()["refresh_token"],
            "client_id": "other-public-client",
        },
    )

    assert response.status_code == status.HTTP_400_BAD_REQUEST
    assert response.json()["error"] == "invalid_grant"


@pytest.mark.asyncio
@pytest.mark.negative
async def test_refresh_token_rejects_inactive_client(
    app: FastAPI,
    client: httpx.AsyncClient,
    verified_user_credentials: UserCredentials,
) -> None:
    """Assert refresh tokens are rejected when their client is inactive."""
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
    async with app.state.core_session_factory() as db_session:
        await db_session.execute(
            update(OAuth2ClientDB)
            .where(OAuth2ClientDB.client_id == "public-client")
            .values(is_active=False)
        )
        await db_session.commit()

    response = await client.post(
        "/oauth2/token",
        data={
            "grant_type": "refresh_token",
            "refresh_token": token_response.json()["refresh_token"],
            "client_id": "public-client",
        },
    )

    assert response.status_code == status.HTTP_401_UNAUTHORIZED


@pytest.mark.asyncio
@pytest.mark.negative
async def test_bearer_auth_requires_stored_access_token(
    app: FastAPI,
    client: httpx.AsyncClient,
    verified_user_credentials: UserCredentials,
) -> None:
    """Assert bearer auth rejects access tokens after persisted revocation."""
    add_oauth2_required_context_route(app)
    login_response = await request_user_token(app, client, verified_user_credentials)
    assert login_response.status_code == status.HTTP_200_OK
    access_token = login_response.json()["access_token"]

    response = await client.get(
        "/test/oauth2/required-context",
        headers={"Authorization": f"Bearer {access_token}"},
    )
    assert response.status_code == status.HTTP_200_OK

    async with app.state.core_session_factory() as db_session:
        await db_session.execute(
            update(OAuth2SessionDB).values(ended_at=datetime.now(UTC))
        )
        await db_session.commit()

    revoked_response = await client.get(
        "/test/oauth2/required-context",
        headers={"Authorization": f"Bearer {access_token}"},
    )

    assert revoked_response.status_code == status.HTTP_401_UNAUTHORIZED


@pytest.mark.asyncio
@pytest.mark.negative
async def test_bearer_auth_rejects_inactive_user_client(
    app: FastAPI,
    client: httpx.AsyncClient,
    verified_user_credentials: UserCredentials,
) -> None:
    """Assert user access tokens stop working when their client is disabled."""
    add_oauth2_required_context_route(app)
    login_response = await request_user_token(app, client, verified_user_credentials)
    assert login_response.status_code == status.HTTP_200_OK
    access_token = login_response.json()["access_token"]

    async with app.state.core_session_factory() as db_session:
        await db_session.execute(
            update(OAuth2ClientDB)
            .where(OAuth2ClientDB.client_id == "test-user-client")
            .values(is_active=False)
        )
        await db_session.commit()

    response = await client.get(
        "/test/oauth2/required-context",
        headers={"Authorization": f"Bearer {access_token}"},
    )

    assert response.status_code == status.HTTP_401_UNAUTHORIZED


@pytest.mark.asyncio
@pytest.mark.negative
async def test_bearer_auth_rejects_access_jti_mismatch(
    app: FastAPI,
    client: httpx.AsyncClient,
    verified_user_credentials: UserCredentials,
) -> None:
    """Assert bearer auth requires JWT and persisted token JTIs to match."""
    add_oauth2_required_context_route(app)
    login_response = await request_user_token(app, client, verified_user_credentials)
    assert login_response.status_code == status.HTTP_200_OK
    access_token = login_response.json()["access_token"]
    async with app.state.core_session_factory() as db_session:
        await db_session.execute(
            update(OAuth2TokenPairDB).values(access_jti="wrong-jti")
        )
        await db_session.commit()

    response = await client.get(
        "/test/oauth2/required-context",
        headers={"Authorization": f"Bearer {access_token}"},
    )

    assert response.status_code == status.HTTP_401_UNAUTHORIZED
