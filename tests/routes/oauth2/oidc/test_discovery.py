"""Black-box HTTP tests for OAuth2 and OpenID Connect discovery metadata."""

from urllib.parse import urlsplit

import httpx
import pytest
from app.oauth2.urls import authorization_server_metadata_path
from fastapi import FastAPI, status

from tests.fixtures.settings import app_settings


pytestmark = pytest.mark.api


def _issuer_endpoint(app: FastAPI, path: str) -> str:
    """Return one application path on the configured issuer origin."""
    issuer = urlsplit(app.state.settings.oauth2.jwt_issuer)
    return f"{issuer.scheme}://{issuer.netloc}{path}"


@pytest.mark.asyncio
async def test_oauth_authorization_server_metadata(
    app: FastAPI,
    client: httpx.AsyncClient,
) -> None:
    """Assert OAuth2 metadata advertises the protocol endpoints."""
    response = await client.get(
        authorization_server_metadata_path(app.state.settings.oauth2.jwt_issuer)
    )

    assert response.status_code == status.HTTP_200_OK
    body = response.json()
    assert body["issuer"] == app.state.settings.oauth2.jwt_issuer
    assert body["authorization_endpoint"] == _issuer_endpoint(app, "/oauth2/authorize")
    assert body["token_endpoint"] == _issuer_endpoint(app, "/oauth2/token")
    assert body["device_authorization_endpoint"] == (
        _issuer_endpoint(app, "/oauth2/device_authorization")
    )
    assert body["revocation_endpoint"] == _issuer_endpoint(app, "/oauth2/revoke")
    assert body["introspection_endpoint"] == _issuer_endpoint(app, "/oauth2/introspect")
    assert "authorization_code" in body["grant_types_supported"]
    assert body["device_authorization_endpoint"] == (
        _issuer_endpoint(app, "/oauth2/device_authorization")
    )
    assert body["code_challenge_methods_supported"] == ["S256"]
    assert "client_secret_post" not in body["token_endpoint_auth_methods_supported"]
    assert "none" in body["token_endpoint_auth_methods_supported"]
    assert "token_endpoint_auth_signing_alg_values_supported" not in body
    assert "scopes_supported" not in body


@pytest.mark.asyncio
@app_settings(
    oauth2={
        "authorization_code_enabled": False,
        "refresh_token_enabled": False,
        "client_credentials_enabled": False,
        "device_code_enabled": False,
        "oidc_enabled": False,
    }
)
async def test_oauth_authorization_server_metadata_reflects_enabled_grants(
    app: FastAPI,
    client: httpx.AsyncClient,
) -> None:
    """Assert OAuth2 metadata declares the configured grant capabilities."""
    response = await client.get(
        authorization_server_metadata_path(app.state.settings.oauth2.jwt_issuer)
    )

    assert response.status_code == status.HTTP_200_OK
    body = response.json()
    assert body["grant_types_supported"] == []
    assert "device_authorization_endpoint" not in body
    assert "token_endpoint" not in body
    assert "revocation_endpoint" not in body
    assert "introspection_endpoint" not in body
    assert body["token_endpoint_auth_methods_supported"] == []
    assert (await client.post("/oauth2/token")).status_code == status.HTTP_404_NOT_FOUND


@pytest.mark.asyncio
@app_settings(
    session={"enabled": False},
    ui={"oauth2_interaction": "disabled"},
    oauth2={
        "authorization_code_enabled": False,
        "refresh_token_enabled": True,
        "client_credentials_enabled": True,
        "device_code_enabled": False,
        "oidc_enabled": False,
    },
)
async def test_machine_oauth2_metadata_omits_browser_capabilities(
    app: FastAPI,
    client: httpx.AsyncClient,
) -> None:
    """Advertise only capabilities available without browser sessions."""
    response = await client.get(
        authorization_server_metadata_path(app.state.settings.oauth2.jwt_issuer)
    )

    assert response.status_code == status.HTTP_200_OK
    body = response.json()
    assert "authorization_endpoint" not in body
    assert body["response_types_supported"] == []
    assert body["code_challenge_methods_supported"] == []
    assert body["grant_types_supported"] == [
        "client_credentials",
        "refresh_token",
    ]
    assert "device_authorization_endpoint" not in body


@pytest.mark.asyncio
@app_settings(
    oauth2={
        "authorization_code_enabled": False,
        "refresh_token_enabled": False,
        "client_credentials_enabled": False,
        "device_code_enabled": True,
        "oidc_enabled": False,
    }
)
async def test_oauth_metadata_advertises_device_code_when_enabled(
    app: FastAPI,
    client: httpx.AsyncClient,
) -> None:
    """Assert OAuth2 metadata declares device code when it is enabled."""
    response = await client.get(
        authorization_server_metadata_path(app.state.settings.oauth2.jwt_issuer)
    )

    assert response.status_code == status.HTTP_200_OK
    body = response.json()
    assert body["grant_types_supported"] == [
        "urn:ietf:params:oauth:grant-type:device_code"
    ]
    assert body["device_authorization_endpoint"] == (
        _issuer_endpoint(app, "/oauth2/device_authorization")
    )
    assert "none" in body["token_endpoint_auth_methods_supported"]


@pytest.mark.asyncio
@app_settings(
    oauth2={
        "authorization_code_enabled": False,
        "refresh_token_enabled": False,
        "client_credentials_enabled": True,
        "device_code_enabled": False,
        "oidc_enabled": False,
    }
)
async def test_client_credentials_metadata_requires_client_authentication(
    app: FastAPI,
    client: httpx.AsyncClient,
) -> None:
    """Do not advertise unauthenticated clients for a confidential-only grant."""
    response = await client.get(
        authorization_server_metadata_path(app.state.settings.oauth2.jwt_issuer)
    )

    assert response.status_code == status.HTTP_200_OK
    body = response.json()
    assert body["grant_types_supported"] == ["client_credentials"]
    assert body["token_endpoint_auth_methods_supported"] == ["client_secret_basic"]
    assert "token_endpoint_auth_signing_alg_values_supported" not in body


@pytest.mark.asyncio
@app_settings(oauth2={"jwks_enabled": True, "jwt_key_id": "test-key"})
async def test_oauth_authorization_server_metadata_includes_jwks_when_enabled(
    app: FastAPI,
    client: httpx.AsyncClient,
) -> None:
    """Assert metadata includes jwks_uri only when JWKS is enabled."""
    response = await client.get(
        authorization_server_metadata_path(app.state.settings.oauth2.jwt_issuer)
    )

    assert response.status_code == status.HTTP_200_OK
    assert response.json()["jwks_uri"] == _issuer_endpoint(app, "/oauth2/jwks.json")


@pytest.mark.asyncio
@app_settings(oauth2={"oidc_enabled": False})
async def test_openid_configuration_is_disabled_by_default(
    app: FastAPI,
    client: httpx.AsyncClient,
) -> None:
    """Assert OIDC discovery is unavailable unless OIDC is enabled."""
    issuer_path = urlsplit(app.state.settings.oauth2.jwt_issuer).path.rstrip("/")

    response = await client.get(f"{issuer_path}/.well-known/openid-configuration")

    assert response.status_code == status.HTTP_404_NOT_FOUND


@pytest.mark.asyncio
@app_settings(oauth2={"oidc_enabled": True, "jwks_enabled": True})
async def test_openid_configuration_when_enabled(
    app: FastAPI,
    client: httpx.AsyncClient,
) -> None:
    """Assert OIDC discovery advertises the optional OIDC endpoints."""
    issuer_path = urlsplit(app.state.settings.oauth2.jwt_issuer).path.rstrip("/")
    response = await client.get(f"{issuer_path}/.well-known/openid-configuration")

    assert response.status_code == status.HTTP_200_OK
    body = response.json()
    assert body["issuer"] == app.state.settings.oauth2.jwt_issuer
    assert body["authorization_endpoint"] == _issuer_endpoint(app, "/oauth2/authorize")
    assert body["token_endpoint"] == _issuer_endpoint(app, "/oauth2/token")
    assert body["userinfo_endpoint"] == _issuer_endpoint(app, "/oauth2/userinfo")
    assert body["jwks_uri"] == _issuer_endpoint(app, "/oauth2/jwks.json")
    assert "openid" in body["scopes_supported"]
    assert set(body["claims_supported"]) == {
        "iss",
        "sub",
        "aud",
        "exp",
        "iat",
        "auth_time",
        "nonce",
        "email",
        "email_verified",
        "name",
        "given_name",
        "family_name",
    }
    assert body["grant_types_supported"] == [
        "authorization_code",
        "client_credentials",
        "refresh_token",
        "urn:ietf:params:oauth:grant-type:device_code",
    ]
    assert body["token_endpoint_auth_methods_supported"] == [
        "client_secret_basic",
        "none",
    ]


@pytest.mark.asyncio
async def test_canonical_metadata_routes_follow_issuer_path_rules(
    app: FastAPI,
    client: httpx.AsyncClient,
) -> None:
    """Assert OAuth and OIDC discovery use their distinct canonical paths."""
    issuer = app.state.settings.oauth2.jwt_issuer
    oauth_path = authorization_server_metadata_path(issuer)
    issuer_path = urlsplit(issuer).path.rstrip("/")
    oidc_path = f"{issuer_path}/.well-known/openid-configuration"

    oauth_response = await client.get(oauth_path)
    oidc_response = await client.get(oidc_path)

    assert oauth_response.status_code == status.HTTP_200_OK
    assert oidc_response.status_code == status.HTTP_200_OK
    assert oauth_response.json()["issuer"] == issuer
    assert oidc_response.json()["issuer"] == issuer
