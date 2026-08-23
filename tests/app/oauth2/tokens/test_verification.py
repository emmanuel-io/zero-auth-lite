"""Tests for OAuth2 access-token verification."""

import base64

import pytest
from app.oauth2.errors import OAuth2AccessTokenInvalidError
from app.oauth2.oidc.keys import OAuth2VerifyKey
from app.oauth2.tokens.access import (
    create_client_access_token_payload,
    create_token_pair_data,
)
from app.oauth2.tokens.verification import verify_access_token
from cryptography.hazmat.primitives.asymmetric import ed25519


pytestmark = pytest.mark.unit

JWT_AUDIENCE = "test-audience"
JWT_ISSUER = "https://issuer.test"


def issue_access_token(
    key: ed25519.Ed25519PrivateKey, *, key_id: str | None = None
) -> str:
    """Issue a test access token with the given signing key."""
    return create_token_pair_data(
        access_payload=create_client_access_token_payload(
            client_id="client",
            audience=JWT_AUDIENCE,
        ),
        access_token_lifetime_seconds=60,
        refresh_token_lifetime_seconds=120,
        jwt_issuer=JWT_ISSUER,
        key=key,
        key_id=key_id,
    ).access_token


def test_single_key_accepts_valid_access_token() -> None:
    """Assert a trusted signing key verifies a valid access token."""
    key = ed25519.Ed25519PrivateKey.generate()

    payload = verify_access_token(
        token=issue_access_token(key),
        jwt_issuer=JWT_ISSUER,
        jwt_audience=JWT_AUDIENCE,
        key=key.public_key(),
    )

    assert payload.subject == "client"
    assert payload.organization is None


def test_key_set_selects_matching_key_id() -> None:
    """Assert rotation key sets select the key named by the JWT header."""
    key = ed25519.Ed25519PrivateKey.generate()
    other_key = ed25519.Ed25519PrivateKey.generate()

    payload = verify_access_token(
        token=issue_access_token(key, key_id="current-key"),
        jwt_issuer=JWT_ISSUER,
        jwt_audience=JWT_AUDIENCE,
        key=(
            OAuth2VerifyKey(kid="other", key=other_key.public_key()),
            OAuth2VerifyKey(kid="current-key", key=key.public_key()),
        ),
    )

    assert payload.subject == "client"


def test_key_set_accepts_previous_key_when_enabled() -> None:
    """Assert token verification can use a previous public key by kid."""
    old_key = ed25519.Ed25519PrivateKey.generate()
    current_key = ed25519.Ed25519PrivateKey.generate()

    payload = verify_access_token(
        token=issue_access_token(old_key, key_id="old-key"),
        jwt_issuer=JWT_ISSUER,
        jwt_audience=JWT_AUDIENCE,
        key=(
            OAuth2VerifyKey(kid="current-key", key=current_key.public_key()),
            OAuth2VerifyKey(kid="old-key", key=old_key.public_key()),
        ),
    )

    assert payload.subject == "client"


@pytest.mark.parametrize(
    "token",
    [
        "not-a-jwt",
        "not-json.payload.signature",
        f"{base64.urlsafe_b64encode(b'[]').decode()}.payload.signature",
        "____.payload.signature",
    ],
)
@pytest.mark.negative
def test_malformed_access_token_is_rejected(token: str) -> None:
    """Assert malformed token structures never cross the trust boundary."""
    with pytest.raises(OAuth2AccessTokenInvalidError):
        verify_access_token(
            token=token,
            jwt_issuer=JWT_ISSUER,
            jwt_audience=JWT_AUDIENCE,
            key=(
                OAuth2VerifyKey(
                    kid="current-key",
                    key=ed25519.Ed25519PrivateKey.generate().public_key(),
                ),
            ),
        )


@pytest.mark.negative
def test_key_set_rejects_unknown_key_id() -> None:
    """Assert an untrusted key identifier is not allowed to choose another key."""
    key = ed25519.Ed25519PrivateKey.generate()

    with pytest.raises(OAuth2AccessTokenInvalidError):
        verify_access_token(
            token=issue_access_token(key, key_id="unknown"),
            jwt_issuer=JWT_ISSUER,
            jwt_audience=JWT_AUDIENCE,
            key=(OAuth2VerifyKey(kid="current", key=key.public_key()),),
        )


@pytest.mark.negative
def test_key_set_rejects_missing_key_id() -> None:
    """Require an explicit key identifier when selecting a rotation key."""
    key = ed25519.Ed25519PrivateKey.generate()

    with pytest.raises(OAuth2AccessTokenInvalidError):
        verify_access_token(
            token=issue_access_token(key),
            jwt_issuer=JWT_ISSUER,
            jwt_audience=JWT_AUDIENCE,
            key=(OAuth2VerifyKey(kid="current", key=key.public_key()),),
        )


@pytest.mark.negative
def test_key_set_rejects_token_when_all_candidate_signatures_fail() -> None:
    """Assert a key set rejects tokens not signed by any trusted key."""
    signing_key = ed25519.Ed25519PrivateKey.generate()
    trusted_key = ed25519.Ed25519PrivateKey.generate()

    with pytest.raises(OAuth2AccessTokenInvalidError):
        verify_access_token(
            token=issue_access_token(signing_key, key_id="trusted"),
            jwt_issuer=JWT_ISSUER,
            jwt_audience=JWT_AUDIENCE,
            key=(OAuth2VerifyKey(kid="trusted", key=trusted_key.public_key()),),
        )
