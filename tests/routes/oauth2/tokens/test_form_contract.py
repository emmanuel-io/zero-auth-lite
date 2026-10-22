"""Shared HTTP input contracts for token revocation and introspection."""

import httpx
import pytest
from app.oauth2.specs import OAuth2Specs
from fastapi import FastAPI, status

from tests.fixtures.oauth2 import create_confidential_machine_client
from tests.fixtures.settings import app_settings
from tests.identifiers import deterministic_uuid


pytestmark = pytest.mark.api


@pytest.mark.asyncio
@pytest.mark.negative
@pytest.mark.parametrize("path", ["/oauth2/revoke", "/oauth2/introspect"])
@pytest.mark.parametrize(
    "token", [None, "", "x" * (OAuth2Specs.PROTOCOL_VALUE_LENGTH_MAX + 1)]
)
@app_settings(oauth2={"allow_client_secret_post": True})
async def test_token_management_rejects_malformed_token(
    app: FastAPI, client: httpx.AsyncClient, path: str, token: str | None
) -> None:
    """Translate token validation while accepting sibling form credentials."""
    secret = await create_confidential_machine_client(app)
    fields = {
        "client_id": str(deterministic_uuid("machine-client")),
        "client_secret": secret,
    }
    if token is not None:
        fields["token"] = token

    response = await client.post(path, data=fields)

    assert response.status_code == status.HTTP_400_BAD_REQUEST
    assert response.json() == {"error": "invalid_request"}


@pytest.mark.asyncio
@pytest.mark.parametrize("path", ["/oauth2/revoke", "/oauth2/introspect"])
@app_settings(oauth2={"allow_client_secret_post": True})
async def test_token_management_accepts_advisory_hint_and_extensions(
    app: FastAPI, client: httpx.AsyncClient, path: str
) -> None:
    """Process a flat token form alongside credentials and ignored extras."""
    secret = await create_confidential_machine_client(app)

    response = await client.post(
        path,
        data={
            "client_id": str(deterministic_uuid("machine-client")),
            "client_secret": secret,
            "token": "unknown-token",
            "token_type_hint": "custom-hint",
            "extension": "ignored",
        },
    )

    assert response.status_code == status.HTTP_200_OK
    assert response.headers["Cache-Control"] == "no-store"
    if path == "/oauth2/introspect":
        assert response.json() == {"active": False}
    else:
        assert response.content == b""
