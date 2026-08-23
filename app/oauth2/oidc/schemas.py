"""Pydantic schemas for OpenID Connect routes."""

from typing import Annotated, NotRequired, TypedDict

from pydantic import AnyUrl, BaseModel, Field

from app.core.types import EmailValue
from app.identity.public_ids import USER_ID_PATTERN
from app.oauth2.schemas import IssuerUrl


class UserInfoResponse(TypedDict):
    """OIDC UserInfo response."""

    sub: Annotated[str, Field(pattern=USER_ID_PATTERN)]
    email: NotRequired[EmailValue]
    email_verified: NotRequired[bool]
    name: NotRequired[str]
    given_name: NotRequired[str]
    family_name: NotRequired[str]


class OpenIDProviderMetadata(BaseModel):
    """Typed OpenID Connect discovery metadata."""

    issuer: IssuerUrl
    authorization_endpoint: AnyUrl
    token_endpoint: AnyUrl
    userinfo_endpoint: AnyUrl
    jwks_uri: AnyUrl
    response_types_supported: list[str]
    grant_types_supported: list[str]
    token_endpoint_auth_methods_supported: list[str]
    subject_types_supported: list[str]
    id_token_signing_alg_values_supported: list[str]
    scopes_supported: list[str]
    claims_supported: list[str]
    code_challenge_methods_supported: list[str]


class JWKRead(BaseModel):
    """Published public JWK."""

    kty: str
    kid: str
    use: str | None = None
    alg: str | None = None
    crv: str | None = None
    x: str | None = None


class JWKSResponse(BaseModel):
    """Public JWKS response."""

    keys: list[JWKRead]
