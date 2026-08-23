"""HTTP response shaping for OAuth2 authorization endpoints."""

from fastapi import Response
from starlette.responses import RedirectResponse

from app.oauth2.authorization.result import (
    AuthorizationConsentPage,
    AuthorizationRedirect,
)
from app.oauth2.errors import OAuth2ProtocolError
from app.oauth2.validation import (
    ERR_INVALID_CLIENT,
    ERR_INVALID_SCOPE,
    ERR_UNAUTHORIZED_CLIENT,
    ERR_UNSUPPORTED_RESPONSE_TYPE,
)


AUTHORIZATION_PROTOCOL_ERRORS = {
    "invalid_request",
    ERR_INVALID_CLIENT,
    ERR_INVALID_SCOPE,
    ERR_UNAUTHORIZED_CLIENT,
    ERR_UNSUPPORTED_RESPONSE_TYPE,
}


def map_authorization_error(exc: ValueError) -> OAuth2ProtocolError:
    """Convert service-level authorization validation failures to protocol errors."""
    error = str(exc)
    if error in AUTHORIZATION_PROTOCOL_ERRORS:
        return OAuth2ProtocolError(error=error)
    return OAuth2ProtocolError(error="invalid_request")


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
