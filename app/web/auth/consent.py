"""Server-rendered OAuth2 consent continuation page."""

from typing import Annotated

from fastapi import APIRouter, Query, Request, Response, status
from starlette.responses import HTMLResponse, RedirectResponse

from app.browser_sessions.dependencies import (
    PublicOptionalBrowserUserContextDep,
    SessionLifecycleServiceDep,
)
from app.oauth2.authorization.dependencies import AuthorizationRequestServiceDep
from app.oauth2.authorization.http import authorization_response
from app.oauth2.authorization.request import AuthorizationRequest
from app.oauth2.authorization.result import AuthorizationRedirect
from app.oauth2.authorization.transaction import (
    AuthorizationTransactionServiceDep,
    hash_authorization_transaction_id,
)
from app.openapi_tags import OAUTH2_AUTHORIZATION_CODE_FLOW_TAG
from app.settings.dependencies import SettingsDep
from app.web.redirects import authentication_entry_url
from app.web.rendering import render_page


router = APIRouter(tags=[OAUTH2_AUTHORIZATION_CODE_FLOW_TAG])


def _invalid_interaction(request: Request) -> HTMLResponse:
    """Render one safe error for missing, expired, or foreign interactions."""
    return render_page(
        request,
        "error.html",
        status_code=status.HTTP_400_BAD_REQUEST,
        title="Authorization unavailable",
        message="This authorization request is invalid or has expired.",
        link_url=None,
        link_label=None,
    )


@router.get("/consent")
async def consent_page(  # noqa: PLR0911, PLR0913
    *,
    request: Request,
    authorization_service: AuthorizationRequestServiceDep,
    transaction_service: AuthorizationTransactionServiceDep,
    lifecycle_service: SessionLifecycleServiceDep,
    user_ctx: PublicOptionalBrowserUserContextDep,
    settings: SettingsDep,
    transaction_id: Annotated[str, Query(min_length=1)],
) -> Response:
    """Bind, continue, and when needed render an OAuth2 interaction."""
    if user_ctx is None:
        return RedirectResponse(
            authentication_entry_url(settings, transaction_id=transaction_id),
            status_code=status.HTTP_303_SEE_OTHER,
        )
    transaction_hash = hash_authorization_transaction_id(
        transaction_id=transaction_id,
        secret=(
            authorization_service.settings.authorization_code_hash_secret.get_secret_value()
        ),
    )
    transaction = await transaction_service.bind_to_user(
        transaction_hash=transaction_hash,
        user_id=user_ctx.user_id,
        organization_id=user_ctx.organization_id,
    )
    if transaction is None:
        return _invalid_interaction(request)
    authorization_request = AuthorizationRequest(
        response_type=transaction.response_type,
        client_id=transaction.client_id,
        redirect_uri=transaction.redirect_uri,
        scope=transaction.scope,
        state=transaction.state,
        nonce=transaction.nonce,
        code_challenge=transaction.code_challenge,
        code_challenge_method=transaction.code_challenge_method,
    )
    try:
        validated = await authorization_service.validate_request(authorization_request)
    except ValueError:
        return _invalid_interaction(request)
    if isinstance(validated, AuthorizationRedirect):
        await transaction_service.consume(
            transaction_hash=transaction_hash,
            user_id=user_ctx.user_id,
            organization_id=user_ctx.organization_id,
        )
        return authorization_response(validated)
    if not validated.client.requires_consent:
        consumed = await transaction_service.consume(
            transaction_hash=transaction_hash,
            user_id=user_ctx.user_id,
            organization_id=user_ctx.organization_id,
        )
        if consumed is None:
            return _invalid_interaction(request)
        result = await authorization_service.authorize_validated(
            user_ctx=user_ctx,
            validated=validated,
        )
        return authorization_response(result)
    result = await authorization_service.authorize_validated(
        user_ctx=user_ctx,
        validated=validated,
    )
    if isinstance(result, AuthorizationRedirect):
        await transaction_service.consume(
            transaction_hash=transaction_hash,
            user_id=user_ctx.user_id,
            organization_id=user_ctx.organization_id,
        )
        return authorization_response(result)
    csrf_token = await lifecycle_service.get_session_csrf(
        session_id=user_ctx.session_id
    )
    return render_page(
        request,
        "auth/consent.html",
        client_name=result.client_name,
        scopes=result.requested_scope.split(),
        transaction_id=transaction_id,
        csrf_token=csrf_token,
    )
