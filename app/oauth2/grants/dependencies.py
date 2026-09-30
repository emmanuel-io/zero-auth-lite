"""Typed FastAPI extraction for shared OAuth2 token-grant inputs."""

from typing import Annotated

from fastapi import Depends, Form

from app.oauth2.grants.parsing import parse_token_grant
from app.oauth2.grants.request import GrantRequest
from app.oauth2.grants.types import OAuth2GrantType
from app.oauth2.specs import OAuth2Specs


class TokenRequestForm:
    """Typed raw form shared by all supported token grants."""

    # FastAPI keeps protocol transport fields explicit for validation and OpenAPI.
    def __init__(  # noqa: PLR0913
        self,
        *,
        grant_type: Annotated[OAuth2GrantType, Form()],
        code: Annotated[
            str | None, Form(max_length=OAuth2Specs.PROTOCOL_VALUE_LENGTH_MAX)
        ] = None,
        redirect_uri: Annotated[
            str | None, Form(max_length=OAuth2Specs.REDIRECT_URI_LENGTH_MAX)
        ] = None,
        code_verifier: Annotated[
            str | None, Form(max_length=OAuth2Specs.CODE_VERIFIER_LENGTH_MAX)
        ] = None,
        refresh_token: Annotated[
            str | None, Form(max_length=OAuth2Specs.PROTOCOL_VALUE_LENGTH_MAX)
        ] = None,
        device_code: Annotated[
            str | None, Form(max_length=OAuth2Specs.PROTOCOL_VALUE_LENGTH_MAX)
        ] = None,
        scope: Annotated[
            str | None, Form(max_length=OAuth2Specs.SCOPE_LIST_LENGTH_MAX)
        ] = None,
        client_id: Annotated[
            str | None, Form(max_length=OAuth2Specs.CLIENT_ID_LENGTH_MAX)
        ] = None,
        client_secret: Annotated[
            str | None, Form(max_length=OAuth2Specs.PROTOCOL_VALUE_LENGTH_MAX)
        ] = None,
    ) -> None:
        """Store form values before grant-specific domain validation."""
        self.grant_type = grant_type
        self.code = code
        self.redirect_uri = redirect_uri
        self.code_verifier = code_verifier
        self.refresh_token = refresh_token
        self.device_code = device_code
        self.scope = scope
        self.client_id = client_id
        self.client_secret = client_secret

    def as_mapping(self) -> dict[str, object]:
        """Return fields in the format consumed by grant parsing."""
        return vars(self)


async def get_token_grant_request(
    form: Annotated[TokenRequestForm, Depends()],
) -> GrantRequest:
    """Convert the typed raw form into a grant-specific domain request."""
    return parse_token_grant(form.as_mapping())


TokenGrantRequestDep = Annotated[GrantRequest, Depends(get_token_grant_request)]


class ClientAuthenticatedForm:
    """Common client credentials accepted by OAuth2 form endpoints."""

    def __init__(
        self,
        client_id: Annotated[
            str | None, Form(max_length=OAuth2Specs.CLIENT_ID_LENGTH_MAX)
        ] = None,
        client_secret: Annotated[
            str | None, Form(max_length=OAuth2Specs.PROTOCOL_VALUE_LENGTH_MAX)
        ] = None,
    ) -> None:
        """Store optional form-based client credentials."""
        self.client_id = client_id
        self.client_secret = client_secret
