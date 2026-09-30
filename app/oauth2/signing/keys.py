"""Lazy key providers with caching for the current signing key pair."""

import base64
import binascii
from dataclasses import dataclass
from functools import lru_cache

from cryptography.hazmat.primitives.asymmetric import ed25519
from pydantic import SecretStr

from app.oauth2.settings import OAuth2Settings


@dataclass(frozen=True, slots=True)
class OAuth2VerifyKey:
    """Configured OAuth2 verification key."""

    kid: str
    key: ed25519.Ed25519PublicKey


def _load_raw_key_bytes(
    *,
    b64_value: str | None,
) -> bytes:
    """Decode configured key material and reject absent or malformed values."""
    if b64_value is None:
        msg = "OAuth2 key material must be configured as base64 settings."
        raise RuntimeError(msg)

    try:
        return base64.b64decode(b64_value, validate=True)
    except (binascii.Error, ValueError) as exc:
        msg = "OAuth2 key material is not valid base64."
        raise RuntimeError(msg) from exc


@lru_cache(maxsize=1)
def get_signing_key(
    signing_private_key_b64: SecretStr | None,
) -> ed25519.Ed25519PrivateKey:
    """Return a cached signing key, revealing its secret only at this boundary."""
    value = (
        signing_private_key_b64.get_secret_value()
        if signing_private_key_b64 is not None
        else None
    )
    return ed25519.Ed25519PrivateKey.from_private_bytes(
        _load_raw_key_bytes(b64_value=value)
    )


@lru_cache(maxsize=1)
def get_verify_key(
    signing_public_key_b64: str,
) -> ed25519.Ed25519PublicKey:
    """Return cached Ed25519 public key from explicit base64 settings."""
    return ed25519.Ed25519PublicKey.from_public_bytes(
        _load_raw_key_bytes(
            b64_value=signing_public_key_b64,
        )
    )


def get_verify_keys(
    settings: OAuth2Settings,
) -> tuple[OAuth2VerifyKey, ...]:
    """Return current and optionally previous verification keys from settings."""
    if settings.signing_key_id is None:
        msg = "OAuth2 verification keys require signing_key_id."
        raise RuntimeError(msg)
    current = OAuth2VerifyKey(
        kid=settings.signing_key_id,
        key=get_verify_key(settings.signing_public_key_b64),
    )
    previous = tuple(
        OAuth2VerifyKey(
            kid=item.kid,
            key=ed25519.Ed25519PublicKey.from_public_bytes(
                _load_raw_key_bytes(b64_value=item.signing_public_key_b64)
            ),
        )
        for item in settings.previous_public_keys
    )
    return (current, *previous)
