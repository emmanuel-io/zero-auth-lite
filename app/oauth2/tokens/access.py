"""Issue OAuth2 access and refresh tokens."""

from dataclasses import dataclass
from datetime import datetime, timedelta, UTC
from secrets import token_urlsafe
from uuid import UUID

from cryptography.hazmat.primitives.asymmetric import ed25519
from joserfc import jwt
from joserfc.jwk import OKPKey

from app.oauth2.principal_types import PrincipalType
from app.oauth2.specs import OAuth2Specs


@dataclass(frozen=True, slots=True)
class AccessTokenPayload:
    """Claims shared by access-token issuance and verification."""

    subject: str
    organization: str | None
    audience: str
    access_jti: str
    client_id: UUID
    scope: str = ""
    principal_type: PrincipalType | None = None


@dataclass(frozen=True, slots=True)
class IssuedTokens:
    """Issued token values and their expiration times."""

    access_token: str
    refresh_token: str | None
    access_jti: str
    access_token_lifetime_seconds: int
    access_expires_at: datetime
    refresh_expires_at: datetime | None


def create_access_token_payload(
    *,
    user_public_id: UUID,
    organization_public_id: UUID,
    audience: str,
    client_id: UUID,
    scope: str = "",
) -> AccessTokenPayload:
    """Create claims for a user's access token."""
    return AccessTokenPayload(
        subject=str(user_public_id),
        organization=str(organization_public_id),
        audience=audience,
        access_jti=token_urlsafe(OAuth2Specs.ACCESS_TOKEN_JTI_BYTES),
        client_id=client_id,
        scope=scope,
    )


def create_client_access_token_payload(
    *,
    client_id: UUID,
    audience: str,
    scope: str = "",
) -> AccessTokenPayload:
    """Create claims for a client-credentials access token."""
    return AccessTokenPayload(
        subject=str(client_id),
        organization=None,
        audience=audience,
        access_jti=token_urlsafe(OAuth2Specs.ACCESS_TOKEN_JTI_BYTES),
        client_id=client_id,
        scope=scope,
        principal_type=PrincipalType.CLIENT,
    )


def create_issued_tokens(  # noqa: PLR0913
    *,
    access_payload: AccessTokenPayload,
    access_token_lifetime_seconds: int,
    refresh_token_lifetime_seconds: int,
    issuer: str,
    key: ed25519.Ed25519PrivateKey | str,
    key_id: str | None = None,
    include_refresh_token: bool = True,
    refresh_deadline: datetime | None = None,
) -> IssuedTokens:
    """Issue tokens, preserving an existing refresh-family deadline on rotation."""
    now = datetime.now(tz=UTC)
    refresh_expires_at = (
        refresh_deadline or now + timedelta(seconds=refresh_token_lifetime_seconds)
        if include_refresh_token
        else None
    )
    access_expires_at = now + timedelta(seconds=access_token_lifetime_seconds)
    if refresh_expires_at is not None:
        access_expires_at = min(access_expires_at, refresh_expires_at)
    actual_access_lifetime_seconds = int((access_expires_at - now).total_seconds())
    if actual_access_lifetime_seconds <= 0:
        msg = "Token-family deadline must be in the future"
        raise ValueError(msg)

    access_token = _create_access_token(
        payload=access_payload,
        now=now,
        expire_at=access_expires_at,
        issuer=issuer,
        key=key,
        key_id=key_id,
    )

    return IssuedTokens(
        access_token=access_token,
        refresh_token=(
            token_urlsafe(OAuth2Specs.REFRESH_TOKEN_BYTES)
            if include_refresh_token
            else None
        ),
        access_jti=access_payload.access_jti,
        access_token_lifetime_seconds=actual_access_lifetime_seconds,
        access_expires_at=access_expires_at,
        refresh_expires_at=refresh_expires_at,
    )


def _create_access_token(  # noqa: PLR0913
    *,
    payload: AccessTokenPayload,
    now: datetime,
    expire_at: datetime,
    issuer: str,
    key: ed25519.Ed25519PrivateKey | str,
    key_id: str | None,
) -> str:
    """Sign one access token from prepared claims."""
    signing_key = OKPKey.import_key(
        key, parameters={"alg": OAuth2Specs.JWT_SIGNING_ALGORITHM}
    )
    header = {"alg": OAuth2Specs.JWT_SIGNING_ALGORITHM, "typ": "JWT"}
    if key_id is not None:
        header["kid"] = key_id

    claims = {
        "sub": payload.subject,
        "aud": payload.audience,
        "jti": payload.access_jti,
        "scope": payload.scope,
        "exp": int(expire_at.timestamp()),
        "iat": int(now.timestamp()),
        "nbf": int(now.timestamp()),
        "iss": issuer,
    }
    if payload.organization is not None:
        claims["organization"] = payload.organization
    claims["client_id"] = str(payload.client_id)
    if payload.principal_type is not None:
        claims["principal_type"] = payload.principal_type.value

    return jwt.encode(
        header=header,
        claims=claims,
        key=signing_key,
        algorithms=[OAuth2Specs.JWT_SIGNING_ALGORITHM],
    )
