"""Pydantic models for all OAuth2 token grant types."""

from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field

from app.oauth2.grants.types import OAuth2GrantType
from app.oauth2.specs import OAuth2Specs


class RefreshTokenGrantRequest(BaseModel):
    """Grant type for refreshing access tokens."""

    grant_type: Literal[OAuth2GrantType.REFRESH_TOKEN]
    refresh_token: Annotated[
        str,
        Field(
            description="Refresh token",
            max_length=OAuth2Specs.PROTOCOL_VALUE_LENGTH_MAX,
        ),
    ]
    client_id: Annotated[
        str | None,
        Field(
            description="Optional client ID",
            max_length=OAuth2Specs.CLIENT_ID_LENGTH_MAX,
        ),
    ] = None
    client_secret: Annotated[
        str | None,
        Field(
            description="Optional client secret",
            max_length=OAuth2Specs.PROTOCOL_VALUE_LENGTH_MAX,
        ),
    ] = None
    scope: Annotated[
        str | None,
        Field(
            description="Requested scopes", max_length=OAuth2Specs.SCOPE_LIST_LENGTH_MAX
        ),
    ] = None

    model_config = ConfigDict(
        extra="forbid",
    )


class AuthorizationCodeGrantRequest(BaseModel):
    """Grant type for exchanging authorization code for tokens."""

    grant_type: Literal[OAuth2GrantType.AUTHORIZATION_CODE]
    code: Annotated[
        str,
        Field(
            description="Authorization code",
            max_length=OAuth2Specs.PROTOCOL_VALUE_LENGTH_MAX,
        ),
    ]
    redirect_uri: Annotated[
        str,
        Field(
            description="Redirect URI", max_length=OAuth2Specs.REDIRECT_URI_LENGTH_MAX
        ),
    ]
    client_id: Annotated[
        str | None,
        Field(description="Client ID", max_length=OAuth2Specs.CLIENT_ID_LENGTH_MAX),
    ] = None
    code_verifier: Annotated[
        str,
        Field(
            description="PKCE code verifier",
            max_length=OAuth2Specs.CODE_VERIFIER_LENGTH_MAX,
        ),
    ]
    client_secret: Annotated[
        str | None,
        Field(
            description="Optional client secret",
            max_length=OAuth2Specs.PROTOCOL_VALUE_LENGTH_MAX,
        ),
    ] = None

    model_config = ConfigDict(
        extra="forbid",
    )


class ClientCredentialsGrantRequest(BaseModel):
    """Grant type for client credentials flow."""

    grant_type: Literal[OAuth2GrantType.CLIENT_CREDENTIALS]
    client_id: Annotated[
        str | None,
        Field(description="Client ID", max_length=OAuth2Specs.CLIENT_ID_LENGTH_MAX),
    ] = None
    client_secret: Annotated[
        str | None,
        Field(
            description="Optional client secret",
            max_length=OAuth2Specs.PROTOCOL_VALUE_LENGTH_MAX,
        ),
    ] = None
    scope: Annotated[
        str | None,
        Field(
            description="Requested scopes", max_length=OAuth2Specs.SCOPE_LIST_LENGTH_MAX
        ),
    ] = None

    model_config = ConfigDict(
        extra="forbid",
    )


class DeviceCodeGrantRequest(BaseModel):
    """Grant type for device code polling."""

    grant_type: Literal[OAuth2GrantType.DEVICE_CODE]
    device_code: Annotated[
        str,
        Field(
            description="Device code", max_length=OAuth2Specs.PROTOCOL_VALUE_LENGTH_MAX
        ),
    ]
    client_id: Annotated[
        str | None,
        Field(description="Client ID", max_length=OAuth2Specs.CLIENT_ID_LENGTH_MAX),
    ] = None
    client_secret: Annotated[
        str | None,
        Field(
            description="Optional client secret",
            max_length=OAuth2Specs.PROTOCOL_VALUE_LENGTH_MAX,
        ),
    ] = None

    model_config = ConfigDict(
        extra="forbid",
    )


GrantRequest = Annotated[
    RefreshTokenGrantRequest
    | AuthorizationCodeGrantRequest
    | ClientCredentialsGrantRequest
    | DeviceCodeGrantRequest,
    Field(discriminator="grant_type"),
]
