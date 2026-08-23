"""Tests for OpenID Connect ID-token issuance."""

from datetime import datetime, UTC

import pytest
from app.oauth2.oidc.id_tokens import create_id_token
from cryptography.hazmat.primitives.asymmetric import ed25519
from joserfc import jwt
from joserfc.jwk import OKPKey


pytestmark = pytest.mark.unit


def test_id_token_contains_authentication_and_profile_claims() -> None:
    """Assert ID tokens explain when and for whom authentication occurred."""
    key = ed25519.Ed25519PrivateKey.generate()
    authenticated_at = datetime(2026, 1, 2, 3, 4, tzinfo=UTC)

    token = create_id_token(
        subject="usr_001P018WN3AT0",
        audience="client",
        jwt_issuer="https://issuer.test",
        lifetime_seconds=60,
        authenticated_at=authenticated_at,
        key=key,
        key_id="current-key",
        email="user@example.com",
        email_verified=True,
        name="Test User",
        given_name="Test",
        family_name="User",
    )
    verifying_key = OKPKey.import_key(key.public_key(), parameters={"alg": "Ed25519"})
    decoded = jwt.decode(token, verifying_key, ["Ed25519"])

    assert decoded.header["kid"] == "current-key"
    assert decoded.claims["auth_time"] == int(authenticated_at.timestamp())
    assert decoded.claims["email"] == "user@example.com"
    assert decoded.claims["email_verified"] is True
    assert decoded.claims["name"] == "Test User"
