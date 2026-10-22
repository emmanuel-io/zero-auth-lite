"""Typed FastAPI inputs for authorization-code endpoints."""

from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field

from app.oauth2.specs import OAuth2Specs


class AuthorizationRequestFields(BaseModel):
    """Transport fields shared by authorization query and form requests."""

    model_config = ConfigDict(extra="ignore")

    response_type: Annotated[
        str, Field(min_length=1, max_length=OAuth2Specs.RESPONSE_TYPE_LENGTH_MAX)
    ]
    client_id: Annotated[
        str, Field(min_length=1, max_length=OAuth2Specs.CLIENT_ID_LENGTH_MAX)
    ]
    redirect_uri: Annotated[
        str, Field(min_length=1, max_length=OAuth2Specs.REDIRECT_URI_LENGTH_MAX)
    ]
    code_challenge: Annotated[
        str,
        Field(
            min_length=OAuth2Specs.CODE_CHALLENGE_LENGTH_MIN,
            max_length=OAuth2Specs.CODE_CHALLENGE_LENGTH_MAX,
        ),
    ]
    code_challenge_method: Annotated[
        str,
        Field(min_length=1, max_length=OAuth2Specs.CODE_CHALLENGE_METHOD_LENGTH_MAX),
    ]
    scope: Annotated[
        str | None, Field(max_length=OAuth2Specs.SCOPE_LIST_LENGTH_MAX)
    ] = None
    state: Annotated[str | None, Field(max_length=OAuth2Specs.STATE_LENGTH_MAX)] = None
    nonce: Annotated[str | None, Field(max_length=OAuth2Specs.NONCE_LENGTH_MAX)] = None


class AuthorizationDecisionForm(BaseModel):
    """Typed consent submission for a validated authorization request."""

    model_config = ConfigDict(extra="ignore")

    transaction_id: Annotated[
        str, Field(min_length=1, max_length=OAuth2Specs.PROTOCOL_VALUE_LENGTH_MAX)
    ]
    decision: Literal["approve", "deny"]
    csrf_token: str | None = None
