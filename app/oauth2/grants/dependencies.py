"""Typed FastAPI extraction for shared OAuth2 token-grant inputs."""

from typing import Annotated

from fastapi import Depends, Form
from pydantic import BaseModel, ConfigDict, Field

from app.oauth2.grants.parsing import parse_token_grant
from app.oauth2.grants.request import GrantRequest
from app.oauth2.grants.types import OAuth2GrantType
from app.oauth2.specs import OAuth2Specs


class TokenRequestForm(BaseModel):
    """Typed raw form shared by all supported token grants."""

    model_config = ConfigDict(extra="ignore")

    grant_type: OAuth2GrantType
    code: Annotated[
        str | None, Field(max_length=OAuth2Specs.PROTOCOL_VALUE_LENGTH_MAX)
    ] = None
    redirect_uri: Annotated[
        str | None, Field(max_length=OAuth2Specs.REDIRECT_URI_LENGTH_MAX)
    ] = None
    code_verifier: Annotated[
        str | None, Field(max_length=OAuth2Specs.CODE_VERIFIER_LENGTH_MAX)
    ] = None
    refresh_token: Annotated[
        str | None, Field(max_length=OAuth2Specs.PROTOCOL_VALUE_LENGTH_MAX)
    ] = None
    device_code: Annotated[
        str | None, Field(max_length=OAuth2Specs.PROTOCOL_VALUE_LENGTH_MAX)
    ] = None
    scope: Annotated[
        str | None, Field(max_length=OAuth2Specs.SCOPE_LIST_LENGTH_MAX)
    ] = None
    client_id: Annotated[
        str | None, Field(max_length=OAuth2Specs.CLIENT_ID_LENGTH_MAX)
    ] = None
    client_secret: Annotated[
        str | None, Field(max_length=OAuth2Specs.PROTOCOL_VALUE_LENGTH_MAX)
    ] = None


async def get_token_grant_request(
    form: Annotated[TokenRequestForm, Form()],
) -> GrantRequest:
    """Convert the typed raw form into a grant-specific domain request."""
    return parse_token_grant(form.model_dump())


TokenGrantRequestDep = Annotated[GrantRequest, Depends(get_token_grant_request)]
