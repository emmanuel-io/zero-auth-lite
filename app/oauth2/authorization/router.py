"""OAuth2 authorization-code protocol router."""

from datetime import datetime, UTC
from typing import Annotated
from urllib.parse import urlencode

from fastapi import APIRouter, Depends, Response, Security, status

from app.browser_sessions.dependencies import (
    CurrentBrowserFormUserContextDep,
    CurrentBrowserUserContextDep,
    PublicOptionalBrowserUserContextDep,
)
from app.oauth2.authorization.dependencies import AuthorizationRequestServiceDep
from app.oauth2.authorization.forms import (
    AuthorizationDecisionForm,
    AuthorizationRequestForm,
    AuthorizationRequestParams,
)
from app.oauth2.authorization.http import (
    authorization_response,
    map_authorization_error,
)
from app.oauth2.authorization.navigation import authorization_login_url
from app.oauth2.authorization.request import AuthorizationRequest
from app.oauth2.authorization.result import (
    AuthorizationConsentPage,
    AuthorizationRedirect,
)
from app.oauth2.authorization.transaction import (
    AuthorizationTransactionServiceDep,
    create_authorization_transaction_id,
    hash_authorization_transaction_id,
)
from app.oauth2.authorization.transaction_dtos import (
    AuthorizationTransactionCreateDTO,
)
from app.oauth2.errors import OAuth2ProtocolError
from app.oauth2.protocol_route import OAuth2ProtocolRoute
from app.oauth2.schemas import OAuth2ErrorResponse
from app.openapi_tags import OAUTH2_AUTHORIZATION_CODE_FLOW_TAG
from app.security.openapi import cookie_sid
from app.settings.dependencies import SettingsDep


router = APIRouter(
    tags=[OAUTH2_AUTHORIZATION_CODE_FLOW_TAG],
    route_class=OAuth2ProtocolRoute,
)


def _authorization_request(
    params: AuthorizationRequestParams | AuthorizationRequestForm,
) -> AuthorizationRequest:
    """Build the shared domain request from typed query or form parameters."""
    return AuthorizationRequest(
        response_type=params.response_type,
        client_id=params.client_id,
        redirect_uri=params.redirect_uri,
        code_challenge=params.code_challenge,
        code_challenge_method=params.code_challenge_method,
        scope=params.scope,
        state=params.state,
        nonce=params.nonce,
    )


@router.get(
    "/authorize",
    status_code=status.HTTP_302_FOUND,
    responses={
        302: {
            "description": (
                "Redirect to the validated client. Success carries code and optional "
                "state; errors carry error, optional error_description/error_uri, "
                "and the original state."
            )
        },
        400: {"description": "Invalid request.", "model": OAuth2ErrorResponse},
        401: {"description": "Browser authentication required."},
    },
)
async def authorize(
    params: Annotated[AuthorizationRequestParams, Depends()],
    authorization_service: AuthorizationRequestServiceDep,
    transaction_service: AuthorizationTransactionServiceDep,
    user_ctx: PublicOptionalBrowserUserContextDep,
    settings: SettingsDep,
) -> Response:
    """Start Authorization Code (+ PKCE) flow."""
    result = await _handle_authorization_request(
        request=_authorization_request(params),
        authorization_service=authorization_service,
        transaction_service=transaction_service,
        user_ctx=user_ctx,
        settings=settings,
    )
    return authorization_response(result)


@router.post(
    "/authorize",
    status_code=status.HTTP_302_FOUND,
    responses={
        302: {
            "description": (
                "Redirect to the validated client. Success carries code and optional "
                "state; errors carry error and the original state."
            )
        },
        400: {
            "description": "Untrusted or malformed request.",
            "model": OAuth2ErrorResponse,
        },
        401: {"description": "Browser authentication required."},
    },
)
async def authorize_form_post(
    params: Annotated[AuthorizationRequestForm, Depends()],
    authorization_service: AuthorizationRequestServiceDep,
    transaction_service: AuthorizationTransactionServiceDep,
    user_ctx: PublicOptionalBrowserUserContextDep,
    settings: SettingsDep,
) -> Response:
    """Process an authorization request submitted as form-urlencoded data."""
    result = await _handle_authorization_request(
        request=_authorization_request(params),
        authorization_service=authorization_service,
        transaction_service=transaction_service,
        user_ctx=user_ctx,
        settings=settings,
    )
    return authorization_response(result)


async def _handle_authorization_request(
    *,
    request: AuthorizationRequest,
    authorization_service: AuthorizationRequestServiceDep,
    transaction_service: AuthorizationTransactionServiceDep,
    user_ctx: CurrentBrowserUserContextDep | None,
    settings: SettingsDep,
) -> AuthorizationRedirect:
    """Run one typed authorization request through the shared service."""
    try:
        validated = await authorization_service.validate_request(request)
    except ValueError as exc:
        raise map_authorization_error(exc) from exc
    if isinstance(validated, AuthorizationRedirect):
        return validated
    if user_ctx is None:
        if not settings.ui.oauth2_interaction_is_builtin:
            return authorization_service.deny_interaction(validated)
        transaction_id = await _create_authorization_transaction(
            request=request,
            authorization_service=authorization_service,
            transaction_service=transaction_service,
            user_ctx=None,
        )
        return AuthorizationRedirect(
            url=authorization_login_url(settings, transaction_id=transaction_id),
            status_code=303,
        )
    try:
        result = await authorization_service.authorize_validated(
            user_ctx=user_ctx,
            validated=validated,
        )
    except ValueError as exc:
        raise map_authorization_error(exc) from exc
    if isinstance(result, AuthorizationConsentPage):
        if not settings.ui.oauth2_interaction_is_builtin:
            return authorization_service.deny_interaction(validated)
        transaction_id = await _create_authorization_transaction(
            request=request,
            authorization_service=authorization_service,
            transaction_service=transaction_service,
            user_ctx=user_ctx,
        )
        return AuthorizationRedirect(
            url=f"/consent?{urlencode({'transaction_id': transaction_id})}",
            status_code=303,
        )
    return result


async def _create_authorization_transaction(
    *,
    request: AuthorizationRequest,
    authorization_service: AuthorizationRequestServiceDep,
    transaction_service: AuthorizationTransactionServiceDep,
    user_ctx: CurrentBrowserUserContextDep | None,
) -> str:
    """Persist trusted browser interaction state behind an opaque handle."""
    transaction_id = create_authorization_transaction_id()
    await transaction_service.create(
        data=AuthorizationTransactionCreateDTO(
            transaction_hash=hash_authorization_transaction_id(
                transaction_id=transaction_id,
                secret=(
                    authorization_service.settings.authorization_code_hash_secret.get_secret_value()
                ),
            ),
            response_type=request.response_type,
            client_id=request.client_id,
            redirect_uri=request.redirect_uri,
            scope=request.scope,
            state=request.state,
            nonce=request.nonce,
            code_challenge=request.code_challenge,
            code_challenge_method=request.code_challenge_method,
            user_id=user_ctx.user_id if user_ctx is not None else None,
            organization_id=user_ctx.organization_id if user_ctx is not None else None,
            expires_at=datetime.now(UTC)
            + authorization_service.settings.authorization_code_ttl_delta,
        )
    )
    return transaction_id


@router.post(
    "/authorize/decision",
    dependencies=[Security(cookie_sid)],
    responses={
        302: {
            "description": (
                "Redirect to the validated client with code or access_denied and "
                "the original state."
            )
        },
        400: {"description": "Invalid request.", "model": OAuth2ErrorResponse},
        401: {"description": "Browser authentication required."},
        403: {
            "description": (
                "CSRF validation failed. Send the browser session's CSRF value "
                "in the optional csrf_token form field or the configured "
                "X-CSRF-Token header."
            )
        },
    },
)
async def authorize_decision(
    decision: Annotated[AuthorizationDecisionForm, Depends()],
    authorization_service: AuthorizationRequestServiceDep,
    transaction_service: AuthorizationTransactionServiceDep,
    user_ctx: CurrentBrowserFormUserContextDep,
) -> Response:
    """Approve or deny a server-bound authorization transaction."""
    transaction = await transaction_service.consume(
        transaction_hash=hash_authorization_transaction_id(
            transaction_id=decision.transaction_id,
            secret=(
                authorization_service.settings.authorization_code_hash_secret.get_secret_value()
            ),
        ),
        user_id=user_ctx.user_id,
        organization_id=user_ctx.organization_id,
    )
    if transaction is None:
        raise OAuth2ProtocolError(
            error="invalid_request",
            error_description="Invalid or expired authorization transaction.",
        )
    params = AuthorizationRequest(
        response_type=transaction.response_type,
        client_id=transaction.client_id,
        redirect_uri=transaction.redirect_uri,
        code_challenge=transaction.code_challenge,
        code_challenge_method=transaction.code_challenge_method,
        scope=transaction.scope,
        state=transaction.state,
        nonce=transaction.nonce,
    )
    try:
        result = await authorization_service.authorize_code(
            user_ctx=user_ctx,
            response_type=params.response_type,
            client_id=params.client_id,
            redirect_uri=params.redirect_uri,
            scope=params.scope,
            state=params.state,
            nonce=params.nonce,
            code_challenge=params.code_challenge,
            code_challenge_method=params.code_challenge_method,
            consent=decision.decision,
        )
    except ValueError as exc:
        raise map_authorization_error(exc) from exc
    return authorization_response(result)
