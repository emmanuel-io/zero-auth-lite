"""Black-box HTTP tests for JWKS exposure and JWT key ids."""

import base64
import json
from typing import cast

import httpx
import pytest
from app.oauth2.oidc.keys import get_verify_key
from fastapi import FastAPI, status

from tests.fixtures.auth import UserCredentials
from tests.fixtures.oauth2 import request_user_token
from tests.fixtures.settings import app_settings


pytestmark = pytest.mark.api


def decode_unverified_jwt_header(token: str) -> dict[str, object]:
    """Decode a JWT header without verifying the signature."""
    header, _payload, _signature = token.split(".")
    padded_header = header + "=" * (-len(header) % 4)
    return cast(
        "dict[str, object]", json.loads(base64.urlsafe_b64decode(padded_header))
    )


@pytest.mark.asyncio
@app_settings(oauth2={"jwks_enabled": False, "oidc_enabled": False})
async def test_jwks_endpoint_is_optional(
    client: httpx.AsyncClient,
) -> None:
    """Assert JWKS is hidden unless explicitly enabled."""
    response = await client.get("/oauth2/jwks.json")

    assert response.status_code == status.HTTP_404_NOT_FOUND


@pytest.mark.asyncio
@app_settings(oauth2={"jwks_enabled": True, "jwt_key_id": "test-main-key"})
async def test_jwks_endpoint_returns_current_public_key(
    client: httpx.AsyncClient,
) -> None:
    """Assert enabled JWKS exposes the configured public verification key."""
    get_verify_key.cache_clear()

    response = await client.get("/oauth2/jwks.json")

    assert response.status_code == status.HTTP_200_OK
    body = response.json()
    assert len(body["keys"]) == 1
    jwk = body["keys"][0]
    assert jwk["kid"] == "test-main-key"
    assert jwk["kty"] == "OKP"
    assert jwk["crv"] == "Ed25519"
    assert jwk["alg"] == "Ed25519"
    assert jwk["use"] == "sig"
    assert jwk["x"]


@pytest.mark.asyncio
@app_settings(oauth2={"jwt_key_id": "test-main-key"})
async def test_access_token_includes_configured_kid(
    app: FastAPI,
    client: httpx.AsyncClient,
    verified_user_credentials: UserCredentials,
) -> None:
    """Assert issued access tokens include a key id when configured."""
    response = await request_user_token(app, client, verified_user_credentials)

    assert response.status_code == status.HTTP_200_OK
    header = decode_unverified_jwt_header(response.json()["access_token"])
    assert header["kid"] == "test-main-key"
