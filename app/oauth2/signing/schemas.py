"""Pydantic schemas for public OAuth2 signing keys."""

from pydantic import BaseModel


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
