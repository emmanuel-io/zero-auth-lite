"""Issue OpenID Connect ID tokens."""

from datetime import datetime, timedelta, UTC

from cryptography.hazmat.primitives.asymmetric import ed25519
from joserfc import jwt
from joserfc.jwk import OKPKey

from app.oauth2.specs import OAuth2Specs


def create_id_token(  # noqa: PLR0913
    *,
    subject: str,
    audience: str,
    jwt_issuer: str,
    lifetime_seconds: int,
    authenticated_at: datetime,
    key: ed25519.Ed25519PrivateKey | str,
    key_id: str | None = None,
    nonce: str | None = None,
    email: str | None = None,
    email_verified: bool | None = None,
    name: str | None = None,
    given_name: str | None = None,
    family_name: str | None = None,
) -> str:
    """Create a signed ID token with optional profile claims."""
    now = datetime.now(tz=UTC)
    signing_key = OKPKey.import_key(
        key, parameters={"alg": OAuth2Specs.JWT_SIGNING_ALGORITHM}
    )
    header = {"alg": OAuth2Specs.JWT_SIGNING_ALGORITHM, "typ": "JWT"}
    if key_id is not None:
        header["kid"] = key_id

    claims: dict[str, object] = {
        "iss": jwt_issuer,
        "sub": subject,
        "aud": audience,
        "exp": int((now + timedelta(seconds=lifetime_seconds)).timestamp()),
        "iat": int(now.timestamp()),
        "auth_time": int(authenticated_at.timestamp()),
    }
    optional_claims: dict[str, object | None] = {
        "nonce": nonce,
        "email": email,
        "email_verified": email_verified,
        "name": name,
        "given_name": given_name,
        "family_name": family_name,
    }
    claims.update(
        {claim: value for claim, value in optional_claims.items() if value is not None}
    )
    return jwt.encode(
        header=header,
        claims=claims,
        key=signing_key,
        algorithms=[OAuth2Specs.JWT_SIGNING_ALGORITHM],
    )
