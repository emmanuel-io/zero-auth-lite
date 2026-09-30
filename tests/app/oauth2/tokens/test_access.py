"""Tests for OAuth2 access-token issuance."""

from datetime import datetime, timedelta, UTC

import pytest
from app.oauth2.principal_types import PrincipalType
from app.oauth2.specs import OAuth2Specs
from app.oauth2.tokens.access import (
    create_client_access_token_payload,
    create_issued_tokens,
)
from cryptography.hazmat.primitives.asymmetric import ed25519
from joserfc import jwt
from joserfc.jwk import OKPKey

from tests.identifiers import deterministic_uuid


pytestmark = pytest.mark.unit

JWT_AUDIENCE = "test-audience"
JWT_ISSUER = "https://issuer.test"
ROTATED_ACCESS_LIFETIME_SECONDS = 29


def test_client_credentials_payload_identifies_client_without_organization() -> None:
    """Assert client credentials use the client as the token subject."""

    payload = create_client_access_token_payload(
        client_id=deterministic_uuid("client"),
        audience=JWT_AUDIENCE,
        scope="read",
    )

    assert payload.subject == str(deterministic_uuid("client"))
    assert payload.client_id == deterministic_uuid("client")
    assert payload.scope == "read"
    assert payload.organization is None
    assert payload.principal_type is PrincipalType.CLIENT


def test_access_token_only_grant_omits_refresh_token_data() -> None:
    """Assert grants can issue an access token without refresh state."""
    tokens = create_issued_tokens(
        access_payload=create_client_access_token_payload(
            client_id=deterministic_uuid("client"),
            audience=JWT_AUDIENCE,
        ),
        access_token_lifetime_seconds=60,
        refresh_token_lifetime_seconds=120,
        issuer=JWT_ISSUER,
        key=ed25519.Ed25519PrivateKey.generate(),
        include_refresh_token=False,
    )

    assert tokens.access_token
    assert tokens.refresh_token is None
    assert tokens.refresh_expires_at is None


def test_issued_access_token_contains_configured_key_id() -> None:
    """Assert key rotation metadata is included in the signed JWT header."""
    key = ed25519.Ed25519PrivateKey.generate()
    tokens = create_issued_tokens(
        access_payload=create_client_access_token_payload(
            client_id=deterministic_uuid("client"),
            audience=JWT_AUDIENCE,
        ),
        access_token_lifetime_seconds=60,
        refresh_token_lifetime_seconds=120,
        issuer=JWT_ISSUER,
        key=key,
        key_id="current-key",
    )

    verifying_key = OKPKey.import_key(
        key.public_key(), parameters={"alg": OAuth2Specs.JWT_SIGNING_ALGORITHM}
    )
    decoded = jwt.decode(
        tokens.access_token,
        verifying_key,
        [OAuth2Specs.JWT_SIGNING_ALGORITHM],
    )

    assert decoded.header["kid"] == "current-key"
    assert "organization" not in decoded.claims
    assert decoded.claims["principal_type"] == "client"


def test_rotated_refresh_token_preserves_family_deadline() -> None:
    """Keep refresh-family lifetime absolute instead of extending on rotation."""
    deadline = datetime.now(UTC) + timedelta(minutes=5)

    tokens = create_issued_tokens(
        access_payload=create_client_access_token_payload(
            client_id=deterministic_uuid("client"),
            audience=JWT_AUDIENCE,
        ),
        access_token_lifetime_seconds=60,
        refresh_token_lifetime_seconds=120,
        issuer=JWT_ISSUER,
        key=ed25519.Ed25519PrivateKey.generate(),
        refresh_deadline=deadline,
    )

    assert tokens.refresh_expires_at == deadline


def test_rotated_access_token_does_not_outlive_family_deadline() -> None:
    """Bound rotated access authority to the absolute refresh-family lifetime."""
    deadline = datetime.now(UTC) + timedelta(seconds=30)

    tokens = create_issued_tokens(
        access_payload=create_client_access_token_payload(
            client_id=deterministic_uuid("client"),
            audience=JWT_AUDIENCE,
        ),
        access_token_lifetime_seconds=60,
        refresh_token_lifetime_seconds=120,
        issuer=JWT_ISSUER,
        key=ed25519.Ed25519PrivateKey.generate(),
        refresh_deadline=deadline,
    )

    assert tokens.access_expires_at == deadline
    assert tokens.access_token_lifetime_seconds == ROTATED_ACCESS_LIFETIME_SECONDS
