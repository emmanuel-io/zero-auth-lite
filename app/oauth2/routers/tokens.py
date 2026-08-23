"""OAuth2 token endpoints."""

import logging
from typing import Annotated

from fastapi import APIRouter, Depends, Form, Response, status

from app.db.dependencies import DbSessionDep, DbSessionFactoryDep
from app.oauth2.authorization.code_exchange import handle_authorization_code_grant
from app.oauth2.clients.auth import ClientAuth, lock_and_reload_token_client
from app.oauth2.clients.auth_dependencies import (
    authenticate_introspection_client,
    authenticate_revoke_client,
    authenticate_token_client_for_grant,
)
from app.oauth2.clients.client_credentials import handle_client_credentials_grant
from app.oauth2.devices.polling import handle_device_code_grant
from app.oauth2.errors import OAuth2ProtocolError
from app.oauth2.grants.dependencies import TokenGrantRequestDep
from app.oauth2.grants.request import (
    AuthorizationCodeGrantRequest,
    ClientCredentialsGrantRequest,
    DeviceCodeGrantRequest,
    RefreshTokenGrantRequest,
)
from app.oauth2.oidc.keys import get_signing_key, get_verify_keys
from app.oauth2.protocol_route import OAuth2ProtocolRoute
from app.oauth2.public_ids import format_oauth2_session_id
from app.oauth2.schemas import (
    OAuth2ErrorResponse,
    TokenIntrospectionResponse,
    TokenPair,
)
from app.oauth2.specs import OAuth2Specs
from app.oauth2.tokens.dependencies import (
    TokenIntrospectionServiceDep,
)
from app.oauth2.tokens.refresh import handle_refresh_token_grant
from app.oauth2.tokens.revocation import TokenRevocationServiceDep
from app.openapi_tags import OAUTH2_TOKEN_PROTOCOL_TAG
from app.settings.dependencies import OAuth2SettingsDep


logger = logging.getLogger(__name__)


def _prevent_token_response_caching(response: Response) -> None:
    """Apply the cache headers required for OAuth2 token responses."""
    response.headers["Cache-Control"] = "no-store"
    response.headers["Pragma"] = "no-cache"


router = APIRouter(route_class=OAuth2ProtocolRoute, tags=[OAUTH2_TOKEN_PROTOCOL_TAG])


@router.post(
    "/token",
    openapi_extra={"security": [{"OAuth2ClientBasic": []}, {}]},
    responses={
        200: {"description": "Token pair successfully generated."},
        400: {
            "description": "Unsupported grant type or malformed request.",
            "model": OAuth2ErrorResponse,
        },
        401: {
            "description": "Invalid OAuth2 client authentication.",
            "model": OAuth2ErrorResponse,
        },
    },
)
# Typed form fields stay visible so invalid requests can be translated at the
# OAuth2 route boundary without losing the OpenAPI contract.
async def issue_token(  # noqa: PLR0913
    *,
    response: Response,
    db_session: DbSessionDep,
    session_factory: DbSessionFactoryDep,
    oauth2_settings: OAuth2SettingsDep,
    client_auth: Annotated[
        ClientAuth | None,
        Depends(authenticate_token_client_for_grant),
    ],
    grant_request: TokenGrantRequestDep,
) -> TokenPair:
    """Issue tokens through one of the explicitly supported OAuth2 grants."""
    _prevent_token_response_caching(response)
    if not oauth2_settings.is_grant_enabled(grant_request.grant_type):
        raise OAuth2ProtocolError(error="unsupported_grant_type")

    if not isinstance(
        grant_request,
        RefreshTokenGrantRequest | DeviceCodeGrantRequest,
    ):
        client_auth = await lock_and_reload_token_client(db_session, client_auth)

    signing_key = get_signing_key(oauth2_settings.prv_key_b64)
    match grant_request:
        case RefreshTokenGrantRequest():
            return await handle_refresh_token_grant(
                grant_request,
                db_session=db_session,
                session_factory=session_factory,
                settings=oauth2_settings,
                client_auth=client_auth,
                signing_key=signing_key,
            )
        case AuthorizationCodeGrantRequest():
            return await handle_authorization_code_grant(
                grant_request,
                db_session=db_session,
                settings=oauth2_settings,
                client_auth=client_auth,
                signing_key=signing_key,
            )
        case ClientCredentialsGrantRequest():
            return await handle_client_credentials_grant(
                grant_request,
                db_session=db_session,
                settings=oauth2_settings,
                client_auth=client_auth,
                signing_key=signing_key,
            )
        case DeviceCodeGrantRequest():
            return await handle_device_code_grant(
                grant_request,
                db_session=db_session,
                session_factory=session_factory,
                settings=oauth2_settings,
                client_auth=client_auth,
                signing_key=signing_key,
            )
        case _:
            raise OAuth2ProtocolError(error="invalid_request")


@router.post(
    "/revoke",
    openapi_extra={"security": [{"OAuth2ClientBasic": []}, {}]},
    responses={
        200: {"description": "Token revoked or already invalid."},
        400: {
            "description": "Missing token or malformed request.",
            "model": OAuth2ErrorResponse,
        },
        401: {
            "description": "Invalid OAuth2 client authentication.",
            "model": OAuth2ErrorResponse,
        },
    },
)
async def revoke_token(
    response: Response,
    revocation_service: TokenRevocationServiceDep,
    client_auth: Annotated[
        ClientAuth | None,
        Depends(authenticate_revoke_client),
    ],
    token: Annotated[
        str, Form(min_length=1, max_length=OAuth2Specs.PROTOCOL_VALUE_LENGTH_MAX)
    ],
    token_type_hint: Annotated[
        str | None, Form(max_length=OAuth2Specs.GRANT_TYPE_LENGTH_MAX)
    ] = None,
) -> Response:
    """Revoke an access or refresh token without revealing token validity."""
    if client_auth is None:
        raise OAuth2ProtocolError(error="invalid_client")

    revoked = await revocation_service.revoke(
        token=token,
        client_id=client_auth.client_id,
        token_type_hint=token_type_hint,
    )
    if revoked is not None:
        logger.info(
            (
                "event=oauth2_token_revoked outcome=attempted client_id=%s "
                "session_id=%s grant_type=%s token_type_hint=%s"
            ),
            client_auth.client_id,
            format_oauth2_session_id(revoked.session_public_id),
            revoked.grant_type,
            token_type_hint,
        )
    _prevent_token_response_caching(response)
    response.status_code = status.HTTP_200_OK
    return response


@router.post(
    "/introspect",
    response_model_exclude_none=True,
    responses={
        400: {"description": "Malformed request.", "model": OAuth2ErrorResponse},
        401: {
            "description": "Invalid OAuth2 client authentication.",
            "model": OAuth2ErrorResponse,
        },
    },
)
# Client credentials and the token form field are separate protocol inputs.
async def introspect_token(  # noqa: PLR0913
    *,
    response: Response,
    introspection_service: TokenIntrospectionServiceDep,
    oauth2_settings: OAuth2SettingsDep,
    client_auth: Annotated[ClientAuth, Depends(authenticate_introspection_client)],
    token: Annotated[
        str, Form(min_length=1, max_length=OAuth2Specs.PROTOCOL_VALUE_LENGTH_MAX)
    ],
    token_type_hint: Annotated[
        str | None, Form(max_length=OAuth2Specs.GRANT_TYPE_LENGTH_MAX)
    ] = None,
) -> TokenIntrospectionResponse:
    """Inspect a token for the authenticated OAuth2 client."""
    _ = token_type_hint
    _prevent_token_response_caching(response)
    return await introspection_service.introspect_token(
        token=token,
        client_id=client_auth.client_id,
        key=get_verify_keys(oauth2_settings),
    )
