"""Framework-light OAuth2 authorization response results."""

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class AuthorizationRedirect:
    """OAuth2 authorization result that redirects the browser."""

    url: str
    status_code: int = 302


@dataclass(frozen=True, slots=True)
class AuthorizationConsentPage:
    """OAuth2 authorization result that asks the user for consent."""

    client_name: str
    requested_scope: str


type AuthorizationResult = AuthorizationRedirect | AuthorizationConsentPage
