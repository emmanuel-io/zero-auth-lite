"""Typed FastAPI forms for device-code endpoints."""

from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field

from app.oauth2.specs import OAuth2Specs


class DeviceAuthorizationForm(BaseModel):
    """Typed device authorization request."""

    model_config = ConfigDict(extra="ignore")

    client_id: Annotated[
        str | None, Field(max_length=OAuth2Specs.CLIENT_ID_LENGTH_MAX)
    ] = None
    client_secret: Annotated[
        str | None, Field(max_length=OAuth2Specs.PROTOCOL_VALUE_LENGTH_MAX)
    ] = None
    scope: Annotated[
        str | None, Field(max_length=OAuth2Specs.SCOPE_LIST_LENGTH_MAX)
    ] = None


class DeviceVerificationForm(BaseModel):
    """Typed browser decision for a device authorization."""

    model_config = ConfigDict(extra="ignore")

    user_code: Annotated[
        str, Field(min_length=1, max_length=OAuth2Specs.PROTOCOL_VALUE_LENGTH_MAX)
    ]
    decision: Literal["approve", "deny"]
    csrf_token: str | None = None
