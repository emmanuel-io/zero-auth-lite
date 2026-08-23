# ruff: noqa: PLR0913
"""OAuth2 device authorization protocol router."""

from typing import Annotated

from fastapi import (
    APIRouter,
    Depends,
    Request,
    Response,
)

from app.db.dependencies import DbSessionDep
from app.oauth2.clients.auth import authenticate_token_client
from app.oauth2.clients.auth_dependencies import authorization_header, form_credential
from app.oauth2.devices.dependencies import DeviceAuthorizationServiceDep
from app.oauth2.devices.forms import (
    DeviceAuthorizationForm,
)
from app.oauth2.errors import OAuth2ProtocolError
from app.oauth2.grants.dependencies import OAuth2ClientBasicDep
from app.oauth2.protocol_route import OAuth2ProtocolRoute
from app.oauth2.schemas import DeviceAuthorizationResponse, OAuth2ErrorResponse
from app.oauth2.urls import public_path_url
from app.openapi_tags import OAUTH2_DEVICE_FLOW_TAG
from app.password.dependencies import PasswordHasherDep


router = APIRouter(
    tags=[OAUTH2_DEVICE_FLOW_TAG],
    route_class=OAuth2ProtocolRoute,
)


@router.post(
    "/device_authorization",
    openapi_extra={"security": [{"OAuth2ClientBasic": []}, {}]},
    responses={
        400: {"description": "Malformed request.", "model": OAuth2ErrorResponse},
        401: {"description": "Invalid client.", "model": OAuth2ErrorResponse},
    },
)
async def device_authorization(
    *,
    response: Response,
    device_authorization_service: DeviceAuthorizationServiceDep,
    request: Request,
    form: Annotated[DeviceAuthorizationForm, Depends()],
    basic_credentials: OAuth2ClientBasicDep,
    db_session: DbSessionDep,
    password_hasher: PasswordHasherDep,
) -> DeviceAuthorizationResponse:
    """Issue device and user codes for OAuth2 device authorization."""
    client_id = await form_credential(
        request,
        name="client_id",
        parsed_value=form.client_id,
    )
    client_secret = await form_credential(
        request,
        name="client_secret",
        parsed_value=form.client_secret,
    )
    client_auth = await authenticate_token_client(
        db_session=db_session,
        password_hasher=password_hasher,
        authorization=authorization_header(basic_credentials),
        client_id=client_id,
        client_secret=client_secret,
        allow_client_secret_post=(
            device_authorization_service.settings.allow_client_secret_post
        ),
    )
    response.headers["Cache-Control"] = "no-store"
    response.headers["Pragma"] = "no-cache"
    try:
        return await device_authorization_service.create_device_authorization(
            client=client_auth.client,
            scope=form.scope,
            verification_uri=public_path_url(
                issuer=device_authorization_service.settings.jwt_issuer,
                path="/oauth2/device/verify",
            ),
        )
    except ValueError as exc:
        raise OAuth2ProtocolError(error=str(exc)) from exc
