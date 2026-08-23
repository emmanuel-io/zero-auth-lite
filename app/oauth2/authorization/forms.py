# ruff: noqa: PLR0913
"""Typed FastAPI inputs for authorization-code endpoints."""

from typing import Annotated, Literal

from fastapi import Form, Query

from app.oauth2.specs import OAuth2Specs


class AuthorizationRequestParams:
    """Typed query parameters for an authorization-code request."""

    def __init__(
        self,
        *,
        response_type: Annotated[
            str, Query(min_length=1, max_length=OAuth2Specs.RESPONSE_TYPE_LENGTH_MAX)
        ],
        client_id: Annotated[
            str, Query(min_length=1, max_length=OAuth2Specs.CLIENT_ID_LENGTH_MAX)
        ],
        redirect_uri: Annotated[
            str, Query(min_length=1, max_length=OAuth2Specs.REDIRECT_URI_LENGTH_MAX)
        ],
        code_challenge: Annotated[
            str,
            Query(
                min_length=OAuth2Specs.CODE_CHALLENGE_LENGTH_MIN,
                max_length=OAuth2Specs.CODE_CHALLENGE_LENGTH_MAX,
            ),
        ],
        code_challenge_method: Annotated[
            str,
            Query(
                min_length=1, max_length=OAuth2Specs.CODE_CHALLENGE_METHOD_LENGTH_MAX
            ),
        ],
        scope: Annotated[
            str | None, Query(max_length=OAuth2Specs.SCOPE_LIST_LENGTH_MAX)
        ] = None,
        state: Annotated[
            str | None, Query(max_length=OAuth2Specs.STATE_LENGTH_MAX)
        ] = None,
        nonce: Annotated[
            str | None, Query(max_length=OAuth2Specs.NONCE_LENGTH_MAX)
        ] = None,
    ) -> None:
        """Store validated authorization parameters."""
        self.response_type = response_type
        self.client_id = client_id
        self.redirect_uri = redirect_uri
        self.code_challenge = code_challenge
        self.code_challenge_method = code_challenge_method
        self.scope = scope
        self.state = state
        self.nonce = nonce


class AuthorizationRequestForm:
    """Typed form parameters for an authorization-code request."""

    def __init__(
        self,
        *,
        response_type: Annotated[
            str, Form(min_length=1, max_length=OAuth2Specs.RESPONSE_TYPE_LENGTH_MAX)
        ],
        client_id: Annotated[
            str, Form(min_length=1, max_length=OAuth2Specs.CLIENT_ID_LENGTH_MAX)
        ],
        redirect_uri: Annotated[
            str, Form(min_length=1, max_length=OAuth2Specs.REDIRECT_URI_LENGTH_MAX)
        ],
        code_challenge: Annotated[
            str,
            Form(
                min_length=OAuth2Specs.CODE_CHALLENGE_LENGTH_MIN,
                max_length=OAuth2Specs.CODE_CHALLENGE_LENGTH_MAX,
            ),
        ],
        code_challenge_method: Annotated[
            str,
            Form(min_length=1, max_length=OAuth2Specs.CODE_CHALLENGE_METHOD_LENGTH_MAX),
        ],
        scope: Annotated[
            str | None, Form(max_length=OAuth2Specs.SCOPE_LIST_LENGTH_MAX)
        ] = None,
        state: Annotated[
            str | None, Form(max_length=OAuth2Specs.STATE_LENGTH_MAX)
        ] = None,
        nonce: Annotated[
            str | None, Form(max_length=OAuth2Specs.NONCE_LENGTH_MAX)
        ] = None,
    ) -> None:
        """Store an authorization request submitted as form data."""
        self.response_type = response_type
        self.client_id = client_id
        self.redirect_uri = redirect_uri
        self.code_challenge = code_challenge
        self.code_challenge_method = code_challenge_method
        self.scope = scope
        self.state = state
        self.nonce = nonce


class AuthorizationDecisionForm:
    """Typed consent submission for a validated authorization request."""

    def __init__(
        self,
        transaction_id: Annotated[
            str, Form(min_length=1, max_length=OAuth2Specs.PROTOCOL_VALUE_LENGTH_MAX)
        ],
        decision: Annotated[Literal["approve", "deny"], Form()],
    ) -> None:
        """Store validated authorization decision fields."""
        self.transaction_id = transaction_id
        self.decision = decision
