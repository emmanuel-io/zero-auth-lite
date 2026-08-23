"""JWKS helpers for OAuth2 access-token verification keys."""

import base64

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from app.oauth2.oidc.keys import OAuth2VerifyKey
from app.oauth2.specs import OAuth2Specs


def _base64url_no_padding(data: bytes) -> str:
    """Return base64url text without padding.

    Args:
        data: Raw bytes to encode.

    Returns:
        str: Base64url encoded text.
    """
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def ed25519_public_key_to_jwk(
    *,
    key: ed25519.Ed25519PublicKey,
    kid: str,
) -> dict[str, str]:
    """Convert an Ed25519 public key to an OKP JWK.

    Args:
        key: Ed25519 public key.
        kid: Required key identifier.

    Returns:
        dict[str, str]: Public JWK dictionary.
    """
    public_bytes = key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return {
        "kty": "OKP",
        "crv": "Ed25519",
        "x": _base64url_no_padding(public_bytes),
        "alg": OAuth2Specs.JWT_SIGNING_ALGORITHM,
        "use": "sig",
        "kid": kid,
    }


def build_jwks(*, keys: tuple[OAuth2VerifyKey, ...]) -> dict[str, list[dict[str, str]]]:
    """Build a JWKS response from configured verification keys.

    Args:
        keys: Current and optional previous verification keys.

    Returns:
        dict[str, list[dict[str, str]]]: JWKS response body.
    """
    return {
        "keys": [ed25519_public_key_to_jwk(key=item.key, kid=item.kid) for item in keys]
    }
