"""Tests for OAuth2 client credential parsing and authentication."""

from typing import TypedDict
from unittest.mock import AsyncMock, patch

import app.oauth2.clients.auth as client_authentication
import pytest
from app.db.models.oauth2_client import OAuth2ClientDB
from app.oauth2.clients.auth import (
    authenticate_token_client,
    BasicClientCredentials,
    lock_and_reload_token_client,
)
from app.oauth2.clients.auth_dependencies import decode_basic_credentials
from app.oauth2.errors import InvalidClientError, OAuth2ProtocolError
from fastapi import FastAPI
from fastapi.security import HTTPBasicCredentials
from sqlalchemy import select, update

from tests.identifiers import deterministic_uuid

from .helpers import (
    CONFIDENTIAL_ID,
    HASHER,
    INACTIVE_ID,
    PASSWORD,
    PUBLIC_ID,
    seed_clients,
)


ENCODED_BASIC_CLIENT_SECRET = "secret%2Bvalue"  # noqa: S105
DECODED_BASIC_CLIENT_SECRET = "secret+value"  # noqa: S105


class ClientAuthKwargs(TypedDict, total=False):
    """Optional credential transports passed to client authentication."""

    basic_credentials: BasicClientCredentials
    client_id: str
    client_secret: str
    allow_client_secret_post: bool


def parsed_basic(client_id: str, client_secret: str) -> BasicClientCredentials:
    """Build already decoded credentials for the domain authentication helper."""
    return BasicClientCredentials(client_id=client_id, client_secret=client_secret)


@pytest.mark.unit
def test_basic_credentials_decode_form_encoded_components() -> None:
    """Decode the form encoding required by OAuth2 client_secret_basic."""
    credentials = decode_basic_credentials(
        HTTPBasicCredentials(
            username="client%2Fidentifier",
            password=ENCODED_BASIC_CLIENT_SECRET,
        )
    )

    assert credentials == BasicClientCredentials(
        client_id="client/identifier",
        client_secret=DECODED_BASIC_CLIENT_SECRET,
    )


@pytest.mark.integration
@pytest.mark.asyncio
async def test_client_authentication_decision_branches(app: FastAPI) -> None:
    """Cover public, Basic, post, inactive, unknown, and mixed credentials."""
    await seed_clients(app)
    async with app.state.core_session_factory() as session:
        public = await authenticate_token_client(
            db_session=session,
            password_hasher=HASHER,
            client_id=str(PUBLIC_ID),
        )
        header = await authenticate_token_client(
            db_session=session,
            password_hasher=HASHER,
            basic_credentials=parsed_basic(str(CONFIDENTIAL_ID), PASSWORD),
        )
        post = await authenticate_token_client(
            db_session=session,
            password_hasher=HASHER,
            client_id=str(CONFIDENTIAL_ID),
            client_secret=PASSWORD,
        )
        assert (public.method, header.method, post.method) == (
            "public",
            "basic",
            "post",
        )

        invalid_calls: list[ClientAuthKwargs] = [
            {"client_id": str(deterministic_uuid("missing"))},
            {"client_id": str(INACTIVE_ID)},
            {"client_id": str(CONFIDENTIAL_ID)},
            {"client_id": str(PUBLIC_ID), "client_secret": ""},
            {"client_id": str(CONFIDENTIAL_ID), "client_secret": "wrong"},
            {
                "basic_credentials": parsed_basic(
                    str(deterministic_uuid("missing")), PASSWORD
                )
            },
            {"basic_credentials": parsed_basic(str(PUBLIC_ID), PASSWORD)},
            {"basic_credentials": parsed_basic(str(CONFIDENTIAL_ID), "wrong")},
        ]
        for kwargs in invalid_calls:
            with pytest.raises(InvalidClientError):
                await authenticate_token_client(
                    db_session=session,
                    password_hasher=HASHER,
                    **kwargs,
                )

        protocol_calls: list[ClientAuthKwargs] = [
            {},
            {
                "basic_credentials": parsed_basic(str(CONFIDENTIAL_ID), PASSWORD),
                "client_id": str(CONFIDENTIAL_ID),
            },
            {
                "client_id": str(CONFIDENTIAL_ID),
                "client_secret": PASSWORD,
                "allow_client_secret_post": False,
            },
        ]
        for kwargs in protocol_calls:
            with pytest.raises(OAuth2ProtocolError):
                await authenticate_token_client(
                    db_session=session,
                    password_hasher=HASHER,
                    **kwargs,
                )


@pytest.mark.integration
@pytest.mark.asyncio
async def test_token_client_lock_rejects_a_concurrent_secret_rotation(
    app: FastAPI,
) -> None:
    """Do not issue from client credentials invalidated during verification."""
    await seed_clients(app)
    async with app.state.core_session_factory() as token_session:
        client_auth = await authenticate_token_client(
            db_session=token_session,
            password_hasher=HASHER,
            basic_credentials=parsed_basic(str(CONFIDENTIAL_ID), PASSWORD),
        )
        rotated_secret_hash = HASHER.hash("rotated-client-secret")
        async with app.state.core_session_factory.begin() as admin_session:
            await admin_session.execute(
                update(OAuth2ClientDB)
                .where(OAuth2ClientDB.client_id == CONFIDENTIAL_ID)
                .values(client_secret=rotated_secret_hash)
            )

        with pytest.raises(InvalidClientError):
            await lock_and_reload_token_client(token_session, client_auth)


@pytest.mark.integration
@pytest.mark.asyncio
async def test_client_authentication_conditionally_upgrades_the_secret_hash(
    app: FastAPI,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Persist a provider-requested client-secret hash upgrade before issuance."""
    await seed_clients(app)
    replacement_hash = "replacement-client-secret-hash"

    async def accept_with_upgrade(
        _password_hasher: object,
        *,
        password: str,
        password_hash: str,
    ) -> tuple[bool, str | None]:
        _ = password, password_hash
        return True, replacement_hash

    monkeypatch.setattr(
        client_authentication,
        "verify_and_update_password",
        accept_with_upgrade,
    )
    async with app.state.core_session_factory() as token_session:
        client_auth = await authenticate_token_client(
            db_session=token_session,
            password_hasher=HASHER,
            basic_credentials=parsed_basic(str(CONFIDENTIAL_ID), PASSWORD),
        )
        current_auth = await lock_and_reload_token_client(token_session, client_auth)

    async with app.state.core_session_factory() as read_session:
        persisted_hash = await read_session.scalar(
            select(OAuth2ClientDB.client_secret).where(
                OAuth2ClientDB.client_id == CONFIDENTIAL_ID
            )
        )
    assert client_auth.client.client_secret == replacement_hash
    assert current_auth is not None
    assert persisted_hash == replacement_hash


@pytest.mark.integration
@pytest.mark.asyncio
async def test_token_client_lock_leaves_read_boundary_to_caller(app: FastAPI) -> None:
    """Keep transaction completion outside the client locking helper."""
    await seed_clients(app)
    async with app.state.core_session_factory() as token_session:
        client_auth = await authenticate_token_client(
            db_session=token_session,
            password_hasher=HASHER,
            basic_credentials=parsed_basic(str(CONFIDENTIAL_ID), PASSWORD),
        )
        commit = AsyncMock(wraps=token_session.commit)

        with patch.object(token_session, "commit", commit):
            current_auth = await lock_and_reload_token_client(
                token_session, client_auth
            )

        assert current_auth is not None
        assert current_auth.client_id == client_auth.client_id
        commit.assert_not_awaited()
