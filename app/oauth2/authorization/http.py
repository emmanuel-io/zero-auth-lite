"""HTTP response shaping for OAuth2 authorization endpoints."""

from urllib.parse import urlencode, urlsplit, urlunsplit

from fastapi import Response
from starlette.responses import RedirectResponse

from app.oauth2.authorization.result import (
    AuthorizationConsentPage,
    AuthorizationRedirect,
)
from app.oauth2.error_codes import OAuth2ErrorCode, OAuth2ValidationReason
from app.oauth2.errors import OAuth2ProtocolError
from app.settings.root import Settings


AUTHORIZATION_ERROR_CODES = {
    OAuth2ErrorCode.INVALID_REQUEST.value: OAuth2ErrorCode.INVALID_REQUEST,
    OAuth2ErrorCode.INVALID_CLIENT.value: OAuth2ErrorCode.INVALID_CLIENT,
    OAuth2ErrorCode.INVALID_SCOPE.value: OAuth2ErrorCode.INVALID_SCOPE,
    OAuth2ErrorCode.UNAUTHORIZED_CLIENT.value: OAuth2ErrorCode.UNAUTHORIZED_CLIENT,
    OAuth2ErrorCode.UNSUPPORTED_RESPONSE_TYPE.value: (
        OAuth2ErrorCode.UNSUPPORTED_RESPONSE_TYPE
    ),
    OAuth2ValidationReason.INVALID_REDIRECT_URI.value: OAuth2ErrorCode.INVALID_REQUEST,
}


def authorization_interaction_entry_url(
    settings: Settings, *, transaction_id: str
) -> str:
    """Return the configured entry point for an authorization interaction."""
    base_url = settings.ui.urls.authorization_interaction
    parsed = urlsplit(base_url)
    return urlunsplit(
        (
            parsed.scheme,
            parsed.netloc,
            parsed.path,
            urlencode({"transaction_id": transaction_id}),
            "",
        )
    )


def map_authorization_error(exc: ValueError) -> OAuth2ProtocolError:
    """Convert service-level authorization validation failures to protocol errors."""
    error = AUTHORIZATION_ERROR_CODES.get(
        str(exc),
        OAuth2ErrorCode.INVALID_REQUEST,
    )
    return OAuth2ProtocolError(error=error)


def authorization_response(
    result: AuthorizationRedirect | AuthorizationConsentPage,
) -> Response:
    """Convert an authorization result into an HTTP response."""
    if not isinstance(result, AuthorizationRedirect):
        msg = "Consent presentation must be handled by the built-in web layer."
        raise TypeError(msg)
    return RedirectResponse(
        url=result.url,
        status_code=result.status_code,
        headers={"Cache-Control": "no-store", "Pragma": "no-cache"},
    )
