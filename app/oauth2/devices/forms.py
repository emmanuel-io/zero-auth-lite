"""Typed FastAPI forms for device-code endpoints."""

from typing import Annotated, Literal

from fastapi import Form

from app.oauth2.grants.dependencies import ClientAuthenticatedForm
from app.oauth2.specs import OAuth2Specs


class DeviceAuthorizationForm(ClientAuthenticatedForm):
    """Typed device authorization request."""

    def __init__(
        self,
        client_id: Annotated[
            str | None, Form(max_length=OAuth2Specs.CLIENT_ID_LENGTH_MAX)
        ] = None,
        client_secret: Annotated[
            str | None, Form(max_length=OAuth2Specs.PROTOCOL_VALUE_LENGTH_MAX)
        ] = None,
        scope: Annotated[
            str | None, Form(max_length=OAuth2Specs.SCOPE_LIST_LENGTH_MAX)
        ] = None,
    ) -> None:
        """Store a device authorization request."""
        super().__init__(client_id=client_id, client_secret=client_secret)
        self.scope = scope


class DeviceVerificationForm:
    """Typed browser decision for a device authorization."""

    def __init__(
        self,
        user_code: Annotated[
            str, Form(min_length=1, max_length=OAuth2Specs.PROTOCOL_VALUE_LENGTH_MAX)
        ],
        decision: Annotated[Literal["approve", "deny"], Form()],
    ) -> None:
        """Store the device verification decision."""
        self.user_code = user_code
        self.decision = decision
