"""Verify OAuth2 access tokens and select trusted signing keys."""

import base64
import binascii
import json
from logging import getLogger

from cryptography.hazmat.primitives.asymmetric import ed25519
from joserfc import jwt
from joserfc.errors import JoseError
from joserfc.jwk import OKPKey
from joserfc.jwt import JWTClaimsRegistry

from app.oauth2.errors import OAuth2AccessTokenInvalidError
from app.oauth2.oidc.keys import OAuth2VerifyKey
from app.oauth2.principal_types import PrincipalType
from app.oauth2.specs import OAuth2Specs
from app.oauth2.tokens.access import AccessTokenPayload


logger = getLogger(__name__)
JWT_LEEWAY_SECONDS = 30


def verify_access_token(
    *,
    token: str,
    jwt_issuer: str,
    jwt_audience: str,
    key: ed25519.Ed25519PublicKey | str | tuple[OAuth2VerifyKey, ...],
) -> AccessTokenPayload:
    """Verify an access token with one key or a rotation key set."""
    if isinstance(key, tuple):
        return _verify_with_key_set(
            token=token,
            jwt_issuer=jwt_issuer,
            jwt_audience=jwt_audience,
            keys=key,
        )
    return _verify_with_key(
        token=token,
        jwt_issuer=jwt_issuer,
        jwt_audience=jwt_audience,
        key=key,
    )


def _verify_with_key(
    *,
    token: str,
    jwt_issuer: str,
    jwt_audience: str,
    key: ed25519.Ed25519PublicKey | str,
) -> AccessTokenPayload:
    """Verify an access token with one trusted public key."""
    verifying_key = OKPKey.import_key(
        key, parameters={"alg": OAuth2Specs.JWT_SIGNING_ALGORITHM}
    )
    claims_registry = JWTClaimsRegistry(
        leeway=JWT_LEEWAY_SECONDS,
        exp={"essential": True},
        iat={"essential": True},
        nbf={"essential": True},
        sub={"essential": True},
        organization={"essential": False},
        aud={"essential": True, "value": jwt_audience},
        jti={"essential": True},
        iss={"essential": True, "value": jwt_issuer},
        principal_type={"essential": False},
    )
    try:
        token_data = jwt.decode(
            value=token,
            key=verifying_key,
            algorithms=[OAuth2Specs.JWT_SIGNING_ALGORITHM],
        )
        claims_registry.validate(token_data.claims)
        return AccessTokenPayload(
            subject=str(token_data.claims["sub"]),
            organization=(
                str(token_data.claims["organization"])
                if token_data.claims.get("organization") is not None
                else None
            ),
            audience=str(token_data.claims["aud"]),
            access_jti=str(token_data.claims["jti"]),
            client_id=str(token_data.claims["client_id"]),
            scope=str(token_data.claims.get("scope", "")),
            principal_type=(
                PrincipalType(str(token_data.claims["principal_type"]))
                if token_data.claims.get("principal_type") is not None
                else None
            ),
        )
    except JoseError as exc:
        logger.warning("Access token rejected due to claim error: %s", str(exc))
        raise OAuth2AccessTokenInvalidError from exc
    except (KeyError, TypeError, ValueError) as exc:
        logger.warning("Access token decoding failed: %s", str(exc))
        raise OAuth2AccessTokenInvalidError from exc


def _verify_with_key_set(
    *,
    token: str,
    jwt_issuer: str,
    jwt_audience: str,
    keys: tuple[OAuth2VerifyKey, ...],
) -> AccessTokenPayload:
    """Select a rotation key by ``kid`` and verify the access token."""
    kid = _read_unverified_kid(token=token)
    candidates = tuple(item for item in keys if item.kid == kid)
    if not candidates:
        raise OAuth2AccessTokenInvalidError

    last_error: OAuth2AccessTokenInvalidError | None = None
    for candidate in candidates:
        try:
            return _verify_with_key(
                token=token,
                jwt_issuer=jwt_issuer,
                jwt_audience=jwt_audience,
                key=candidate.key,
            )
        except OAuth2AccessTokenInvalidError as exc:
            last_error = exc
    raise OAuth2AccessTokenInvalidError from last_error


def _read_unverified_kid(*, token: str) -> str:
    """Read only the untrusted JWT key identifier used for key selection."""
    try:
        header_segment = token.split(".", 1)[0]
        padded = header_segment + "=" * (-len(header_segment) % 4)
        header = json.loads(base64.urlsafe_b64decode(padded))
    except (
        binascii.Error,
        UnicodeDecodeError,
        ValueError,
        TypeError,
        json.JSONDecodeError,
    ) as exc:
        raise OAuth2AccessTokenInvalidError from exc
    if not isinstance(header, dict):
        raise OAuth2AccessTokenInvalidError
    kid = header.get("kid")
    if not isinstance(kid, str) or not kid:
        raise OAuth2AccessTokenInvalidError
    return kid
