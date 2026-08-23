"""Tests for OAuth2 and composition consistency."""

from datetime import datetime, UTC

import pytest
from app.browser_sessions.settings import SessionSettings
from app.oauth2.clients.auth import authenticate_token_client
from app.oauth2.errors import InvalidClientError
from app.oauth2.oidc.id_tokens import create_id_token
from app.oauth2.oidc.jwks import ed25519_public_key_to_jwk
from app.oauth2.settings import OAuth2Settings
from app.password.pwdlib_hasher import PwdlibPasswordHasher
from cryptography.hazmat.primitives.asymmetric import ed25519
from fastapi import status
from joserfc import jwt
from joserfc.jwk import OKPKey
from pydantic import ValidationError
from sqlalchemy.ext.asyncio import AsyncSession


pytestmark = pytest.mark.unit


def test_ed25519_is_exposed_as_the_fully_specified_jose_algorithm() -> None:
    """Assert signing and JWKS metadata use RFC 9864's Ed25519 identifier."""
    key = ed25519.Ed25519PrivateKey.generate()
    authenticated_at = datetime(2025, 1, 2, 3, 4, tzinfo=UTC)

    token = create_id_token(
        subject="usr_0000000000001",
        audience="client",
        jwt_issuer="https://issuer.example",
        lifetime_seconds=60,
        authenticated_at=authenticated_at,
        key=key,
    )
    decoded = jwt.decode(
        token,
        OKPKey.import_key(key.public_key(), parameters={"alg": "Ed25519"}),
        algorithms=["Ed25519"],
    )
    jwk = ed25519_public_key_to_jwk(key=key.public_key(), kid=None)

    assert decoded.header["alg"] == "Ed25519"
    assert decoded.claims["auth_time"] == int(authenticated_at.timestamp())
    assert jwk["alg"] == "Ed25519"
    assert jwk["crv"] == "Ed25519"


@pytest.mark.asyncio
@pytest.mark.integration
async def test_unknown_client_credentials_return_invalid_client(
    db_session: AsyncSession,
) -> None:
    """Assert failed client authentication uses the OAuth2 authentication error."""
    with pytest.raises(InvalidClientError) as exc_info:
        await authenticate_token_client(
            db_session=db_session,
            password_hasher=PwdlibPasswordHasher(),
            client_id="missing-client",
        )

    assert exc_info.value.error == "invalid_client"
    assert exc_info.value.status_code == status.HTTP_401_UNAUTHORIZED
    assert "WWW-Authenticate" not in exc_info.value.headers


@pytest.mark.parametrize(
    ("settings_type", "kwargs"),
    [
        (OAuth2Settings, {"access_token_lifetime_seconds": 0}),
        (OAuth2Settings, {"authorization_code_ttl_seconds": -1}),
        (SessionSettings, {"ttl_seconds": 0}),
        (
            SessionSettings,
            {"ttl_seconds": 3_600, "absolute_ttl_seconds": 1_800},
        ),
        (SessionSettings, {"slide_seconds": 3_601, "ttl_seconds": 3_600}),
    ],
)
@pytest.mark.negative
def test_invalid_lifetimes_are_rejected(
    settings_type: type[OAuth2Settings] | type[SessionSettings],
    kwargs: dict[str, int],
) -> None:
    """Assert token and session lifetimes cannot create invalid runtime states."""
    with pytest.raises(ValidationError):
        settings_type(**kwargs)
