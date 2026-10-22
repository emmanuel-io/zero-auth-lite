"""Typed token fields shared by revocation and introspection."""

from typing import Annotated

from pydantic import BaseModel, ConfigDict, Field

from app.oauth2.specs import OAuth2Specs


class TokenManagementForm(BaseModel):
    """Token material validated separately from client authentication."""

    # Client-authentication dependencies read credentials from the same form.
    model_config = ConfigDict(extra="ignore")

    token: Annotated[
        str, Field(min_length=1, max_length=OAuth2Specs.PROTOCOL_VALUE_LENGTH_MAX)
    ]
    token_type_hint: Annotated[
        str | None, Field(max_length=OAuth2Specs.GRANT_TYPE_LENGTH_MAX)
    ] = None
