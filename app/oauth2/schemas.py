"""Pydantic schemas for OAuth2 and OpenID Connect routes."""

from typing import Annotated, Literal

from pydantic import AnyUrl, BaseModel, Field, UrlConstraints


IssuerUrl = Annotated[AnyUrl, UrlConstraints(preserve_empty_path=True)]


OAuth2ErrorCode = Literal[
    "invalid_request",
    "invalid_client",
    "invalid_grant",
    "unauthorized_client",
    "unsupported_grant_type",
    "invalid_scope",
    "access_denied",
    "authorization_pending",
    "slow_down",
    "expired_token",
    "unsupported_token_type",
    "unsupported_response_type",
    "server_error",
    "temporarily_unavailable",
    "invalid_token",
    "insufficient_scope",
]


class OAuth2ErrorResponse(BaseModel):
    """RFC-style OAuth2 error response."""

    error: OAuth2ErrorCode
    error_description: str | None = None
    error_uri: AnyUrl | None = None


class TokenPair(BaseModel):
    """Access-token response with optional refresh and OpenID Connect tokens."""

    access_token: Annotated[str, Field(description="Signed JWT access token")]
    refresh_token: Annotated[
        str | None,
        Field(description="Opaque refresh token"),
    ] = None
    id_token: Annotated[
        str | None,
        Field(description="OIDC ID token when openid scope is requested"),
    ] = None
    token_type: Annotated[
        Literal["bearer"],
        Field(description="Token type (always bearer)"),
    ] = "bearer"  # noqa: S105

    expires_in: Annotated[
        int,
        Field(
            description="Time in seconds until the access token expires",
            gt=0,
        ),
    ]

    model_config = {
        "json_schema_extra": {
            "example": {
                "access_token": "eyJhbGciOiJFZDI1NTE5IiwidHlwIjoiSldUIn0…",
                "refresh_token": "def50200b…",
                "token_type": "bearer",
                "expires_in": 900,
            }
        }
    }


class TokenIntrospectionResponse(BaseModel):
    """RFC 7662-style token introspection response."""

    active: bool
    scope: str | None = None
    client_id: str | None = None
    token_type: Literal["bearer"] | None = None
    exp: int | None = None
    iat: int | None = None
    nbf: int | None = None
    sub: str | None = None
    aud: str | list[str] | None = None
    iss: str | None = None
    jti: str | None = None


class DeviceAuthorizationResponse(BaseModel):
    """OAuth2 device authorization response."""

    device_code: str
    user_code: str
    verification_uri: AnyUrl
    verification_uri_complete: AnyUrl
    expires_in: Annotated[int, Field(gt=0)]
    interval: Annotated[int, Field(gt=0)]


class OAuth2AuthorizationServerMetadata(BaseModel):
    """Typed OAuth2 authorization server metadata."""

    issuer: IssuerUrl
    authorization_endpoint: AnyUrl | None = None
    token_endpoint: AnyUrl | None = None
    revocation_endpoint: AnyUrl | None = None
    introspection_endpoint: AnyUrl | None = None
    jwks_uri: AnyUrl | None = None
    device_authorization_endpoint: AnyUrl | None = None
    response_types_supported: list[str]
    grant_types_supported: list[str]
    token_endpoint_auth_methods_supported: list[str]
    revocation_endpoint_auth_methods_supported: list[str]
    introspection_endpoint_auth_methods_supported: list[str]
    code_challenge_methods_supported: list[str]
