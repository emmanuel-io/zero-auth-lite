"""Typed FastAPI inputs for authorization-code endpoints."""

from typing import Annotated, Literal

from fastapi import Form
from pydantic import BaseModel, ConfigDict, Field

from app.oauth2.specs import OAuth2Specs


class AuthorizationRequestFields(BaseModel):
    """Typed query parameters for an authorization-code request."""

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


class AuthorizationDecisionForm:
    """Typed consent submission for a validated authorization request."""

    def __init__(
        self,
        transaction_id: Annotated[
            str, Form(min_length=1, max_length=OAuth2Specs.PROTOCOL_VALUE_LENGTH_MAX)
        ],
        decision: Annotated[Literal["approve", "deny"], Form()],
        csrf_token: Annotated[str | None, Form()] = None,
    ) -> None:
        """Store validated authorization decision fields."""
        self.transaction_id = transaction_id
        self.decision = decision
        self.csrf_token = csrf_token
