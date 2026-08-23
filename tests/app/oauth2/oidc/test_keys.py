"""Tests for OAuth2 key-loading helpers."""

import base64

import app.oauth2.oidc.keys as key_module
import pytest
from app.oauth2.settings import (
    OAuth2PreviousPublicKeySettings,
    OAuth2Settings,
)
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519


pytestmark = pytest.mark.unit


def _raw_public_key_b64(key: ed25519.Ed25519PrivateKey) -> str:
    """Return the base64 raw public key bytes for a private key."""
    raw_key = key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return base64.b64encode(raw_key).decode()


@pytest.mark.negative
def test_load_raw_key_bytes_rejects_missing_and_malformed_values() -> None:
    """Assert key material loader rejects absent and invalid base64 settings."""
    with pytest.raises(RuntimeError, match="must be configured"):
        key_module._load_raw_key_bytes(b64_value=None)  # noqa: SLF001

    with pytest.raises(RuntimeError, match="not valid base64"):
        key_module._load_raw_key_bytes(b64_value="not base64")  # noqa: SLF001


def test_get_verify_keys_includes_previous_rotation_keys() -> None:
    """Assert verification keys include configured previous rotation keys."""
    current_key = ed25519.Ed25519PrivateKey.generate()
    previous_key = ed25519.Ed25519PrivateKey.generate()
    settings = OAuth2Settings(
        pub_key_b64=_raw_public_key_b64(current_key),
        jwt_key_id="current",
        previous_public_keys=[
            OAuth2PreviousPublicKeySettings(
                kid="previous",
                pub_key_b64=_raw_public_key_b64(previous_key),
            )
        ],
    )
    key_module.get_verify_key.cache_clear()

    verify_keys = key_module.get_verify_keys(settings)

    assert [verify_key.kid for verify_key in verify_keys] == ["current", "previous"]
