"""External-frontend JSON adapters for OAuth2 user interactions."""

from typing import Annotated

from fastapi import APIRouter, Path, Response, status

from app.api.error_responses import app_error_responses
from app.api.v1.oauth2_interactions.errors import OAuth2InteractionInvalidError
from app.api.v1.oauth2_interactions.schemas import (
    AuthorizationConsentRequiredResponse,
    AuthorizationInteractionResponse,
    AuthorizationRedirectResponse,
    DeviceInteractionResponse,
    OAuth2InteractionDecisionRequest,
)
from app.browser_sessions.dependencies import CurrentBrowserUserContextDep
from app.browser_sessions.errors import (
    BrowserSessionInvalidError,
    CSRF_ERRORS,
)
from app.oauth2.authorization.interaction import AuthorizationInteractionServiceDep
from app.oauth2.authorization.result import AuthorizationConsentPage
from app.oauth2.devices.dependencies import DeviceAuthorizationServiceDep
from app.oauth2.specs import OAuth2Specs
from app.openapi_tags import OAUTH2_INTERACTION_V1_TAG


INTERACTION_ERROR_RESPONSES = app_error_responses(
    OAuth2InteractionInvalidError,
    BrowserSessionInvalidError,
    descriptions={400: "Invalid, expired, consumed, or foreign OAuth2 interaction."},
)
INTERACTION_MUTATION_ERROR_RESPONSES = app_error_responses(
    OAuth2InteractionInvalidError,
    BrowserSessionInvalidError,
    *CSRF_ERRORS,
    descriptions={
        400: "Invalid, expired, consumed, or foreign OAuth2 interaction.",
        403: "Missing or invalid browser-session CSRF proof.",
    },
)


def _no_store(response: Response) -> None:
    """Prevent browsers and intermediaries from retaining interaction state."""
    response.headers["Cache-Control"] = "no-store"
    response.headers["Pragma"] = "no-cache"


authorization_router = APIRouter(tags=[OAUTH2_INTERACTION_V1_TAG])
device_router = APIRouter(tags=[OAUTH2_INTERACTION_V1_TAG])


@authorization_router.post(
    "/authorization-interactions/{transaction_id}",
    responses=INTERACTION_MUTATION_ERROR_RESPONSES,
)
async def continue_authorization_interaction(
    transaction_id: Annotated[
        str, Path(min_length=1, max_length=OAuth2Specs.PROTOCOL_VALUE_LENGTH_MAX)
    ],
    response: Response,
    service: AuthorizationInteractionServiceDep,
    user_ctx: CurrentBrowserUserContextDep,
) -> AuthorizationInteractionResponse:
    """CSRF-protect, bind, and continue one external authorization transaction."""
    _no_store(response)
    result = await service.continue_interaction(
        transaction_id=transaction_id,
        user_ctx=user_ctx,
    )
    if result is None:
        raise OAuth2InteractionInvalidError
    if isinstance(result, AuthorizationConsentPage):
        return AuthorizationConsentRequiredResponse(
            client_name=result.client_name,
            scopes=result.requested_scope.split(),
        )
    return AuthorizationRedirectResponse(redirect_url=result.url)


@authorization_router.post(
    "/authorization-interactions/{transaction_id}/decision",
    responses=INTERACTION_MUTATION_ERROR_RESPONSES,
)
async def decide_authorization_interaction(
    transaction_id: Annotated[
        str, Path(min_length=1, max_length=OAuth2Specs.PROTOCOL_VALUE_LENGTH_MAX)
    ],
    payload: OAuth2InteractionDecisionRequest,
    response: Response,
    service: AuthorizationInteractionServiceDep,
    user_ctx: CurrentBrowserUserContextDep,
) -> AuthorizationRedirectResponse:
    """Consume an authorization transaction through a CSRF-protected decision."""
    _no_store(response)
    result = await service.decide(
        transaction_id=transaction_id,
        decision=payload.decision,
        user_ctx=user_ctx,
    )
    if result is None:
        raise OAuth2InteractionInvalidError
    return AuthorizationRedirectResponse(redirect_url=result.url)


@device_router.get(
    "/device-interactions/{user_code}",
    responses=INTERACTION_ERROR_RESPONSES,
)
async def get_device_interaction(
    user_code: Annotated[
        str, Path(min_length=1, max_length=OAuth2Specs.PROTOCOL_VALUE_LENGTH_MAX)
    ],
    response: Response,
    service: DeviceAuthorizationServiceDep,
    user_ctx: CurrentBrowserUserContextDep,
) -> DeviceInteractionResponse:
    """Return one live device interaction for an authenticated external UI."""
    _no_store(response)
    interaction = await service.get_device_interaction(
        user_ctx=user_ctx,
        user_code=user_code,
    )
    if interaction is None:
        raise OAuth2InteractionInvalidError
    return DeviceInteractionResponse(
        client_name=interaction.client_name,
        scopes=list(interaction.scopes),
    )


@device_router.post(
    "/device-interactions/{user_code}/decision",
    status_code=status.HTTP_204_NO_CONTENT,
    responses=INTERACTION_MUTATION_ERROR_RESPONSES
    | {204: {"description": "Device authorization decision recorded."}},
)
async def decide_device_interaction(
    user_code: Annotated[
        str, Path(min_length=1, max_length=OAuth2Specs.PROTOCOL_VALUE_LENGTH_MAX)
    ],
    payload: OAuth2InteractionDecisionRequest,
    response: Response,
    service: DeviceAuthorizationServiceDep,
    user_ctx: CurrentBrowserUserContextDep,
) -> None:
    """Apply a CSRF-protected external device authorization decision."""
    _no_store(response)
    decided = await service.decide_device_authorization(
        user_ctx=user_ctx,
        user_code=user_code,
        approve=payload.decision == "approve",
    )
    if not decided:
        raise OAuth2InteractionInvalidError


def create_oauth2_interaction_router(
    *, authorization_code_enabled: bool, device_code_enabled: bool
) -> APIRouter:
    """Compose only the JSON interaction contracts backed by enabled grants."""
    router = APIRouter()
    if authorization_code_enabled:
        router.include_router(authorization_router)
    if device_code_enabled:
        router.include_router(device_router)
    return router
