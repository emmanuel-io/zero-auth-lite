"""OAuth2 device authorization protocol router."""

from typing import Annotated

from fastapi import (
    APIRouter,
    Depends,
    Request,
    Response,
)

from app.db.dependencies import DbSessionDep
from app.http_paths import OAUTH2_DEVICE_AUTHORIZATION_PATH
from app.oauth2.clients.auth import authenticate_token_client
from app.oauth2.clients.auth_dependencies import (
    decode_basic_credentials,
    form_credential,
    OAuth2ClientBasicDep,
)
from app.oauth2.devices.dependencies import DeviceAuthorizationServiceDep
from app.oauth2.devices.forms import (
    DeviceAuthorizationForm,
)
from app.oauth2.protocol_parameters import reject_repeated_protocol_parameters
from app.oauth2.protocol_route import OAuth2ProtocolRoute
from app.oauth2.schemas import DeviceAuthorizationResponse, OAuth2ErrorResponse
from app.openapi_tags import OAUTH2_DEVICE_FLOW_TAG
from app.password.dependencies import PasswordHasherDep
from app.settings.dependencies import SettingsDep


router = APIRouter(
    tags=[OAUTH2_DEVICE_FLOW_TAG],
    route_class=OAuth2ProtocolRoute,
    dependencies=[Depends(reject_repeated_protocol_parameters)],
)


@router.post(
    OAUTH2_DEVICE_AUTHORIZATION_PATH,
    openapi_extra={"security": [{"OAuth2ClientBasic": []}, {}]},
    responses={
        400: {"description": "Malformed request.", "model": OAuth2ErrorResponse},
        401: {"description": "Invalid client.", "model": OAuth2ErrorResponse},
    },
)
# Keep protocol transport fields explicit for FastAPI validation and OpenAPI.
async def device_authorization(  # noqa: PLR0913
    *,
    response: Response,
    device_authorization_service: DeviceAuthorizationServiceDep,
    request: Request,
    form: Annotated[DeviceAuthorizationForm, Depends()],
    basic_credentials: OAuth2ClientBasicDep,
    db_session: DbSessionDep,
    password_hasher: PasswordHasherDep,
    settings: SettingsDep,
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
        basic_credentials=decode_basic_credentials(basic_credentials),
        client_id=client_id,
        client_secret=client_secret,
        allow_client_secret_post=(
            device_authorization_service.settings.allow_client_secret_post
        ),
    )
    response.headers["Cache-Control"] = "no-store"
    response.headers["Pragma"] = "no-cache"
    return await device_authorization_service.create_device_authorization(
        client=client_auth.client,
        scope=form.scope,
        verification_uri=settings.ui.urls.device_interaction,
    )
