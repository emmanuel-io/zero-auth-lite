"""Pure validation helpers shared across OAuth2 flow services."""

from __future__ import annotations

import re
from typing import TYPE_CHECKING
from urllib.parse import urlsplit

from app.oauth2.oidc.claims import scope_includes_openid
from app.oauth2.settings import OAuth2GrantType


if TYPE_CHECKING:
    from app.identity.dtos import IdentityUserDTO
    from app.oauth2.clients.dtos import OAuth2ClientReadDTO
    from app.oauth2.settings import OAuth2Settings


ERR_INVALID_CLIENT = "invalid_client"
ERR_INVALID_REQUEST = "invalid_request"
ERR_INVALID_REDIRECT_URI = "invalid_redirect_uri"
ERR_INVALID_SCOPE = "invalid_scope"
ERR_UNAUTHORIZED_CLIENT = "unauthorized_client"
ERR_UNSUPPORTED_GRANT_TYPE = "unsupported_grant_type"
ERR_UNSUPPORTED_RESPONSE_TYPE = "unsupported_response_type"
PKCE_CHALLENGE_PATTERN = re.compile(r"^[A-Za-z0-9_-]{43}$")


def normalize_scope(scope: str | None) -> str:
    """Return a stable OAuth2 scope string.

    Args:
        scope: Raw scope string.

    Returns:
        str: Space-separated unique scope names preserving request order.
    """
    if not scope:
        return ""
    seen: set[str] = set()
    scopes: list[str] = []
    for item in scope.split():
        if item not in seen:
            seen.add(item)
            scopes.append(item)
    return " ".join(scopes)


def validate_requested_scope(
    *,
    requested_scope: str,
    allowed_scopes: list[str],
) -> None:
    """Validate that requested scopes are registered for the client.

    Args:
        requested_scope: Requested OAuth2 scope string.
        allowed_scopes: Client-registered scopes.

    Raises:
        ValueError: If any requested scope is not allowed.
    """
    if set(requested_scope.split()) - set(allowed_scopes):
        raise ValueError(ERR_INVALID_SCOPE)


def validate_oidc_scope_enabled(
    *,
    requested_scope: str,
    oidc_enabled: bool,
) -> None:
    """Reject OIDC scopes when the optional OIDC layer is disabled.

    Args:
        requested_scope: Normalized space-separated scope string.
        oidc_enabled: Whether OIDC support is enabled.

    Raises:
        ValueError: If openid is requested while OIDC is disabled.
    """
    if scope_includes_openid(requested_scope) and not oidc_enabled:
        raise ValueError(ERR_INVALID_SCOPE)


def user_display_name(user: IdentityUserDTO) -> str | None:
    """Build a display name for OIDC profile claims.

    Args:
        user: User database row.

    Returns:
        str | None: Display name, or None when no profile name is available.
    """
    name = " ".join(part for part in [user.first_name, user.last_name] if part)
    return name or None


def client_allows_grant(
    client: OAuth2ClientReadDTO, grant_type: OAuth2GrantType
) -> bool:
    """Return whether a client is configured for a grant type."""
    return grant_type.value in client.grant_types


def should_issue_refresh_token(
    *, settings: OAuth2Settings, client: OAuth2ClientReadDTO | None
) -> bool:
    """Return whether a flow should issue refresh-token material."""
    return settings.is_grant_enabled(OAuth2GrantType.refresh_token) and (
        client is None or client_allows_grant(client, OAuth2GrantType.refresh_token)
    )


def normalize_user_code(user_code: str) -> str:
    """Return a normalized device user code.

    Args:
        user_code: Raw user-entered device code.

    Returns:
        str: Uppercase code with spaces removed.
    """
    return user_code.strip().replace(" ", "").upper()


def validate_redirect_uri(redirect_uri: str) -> None:
    """Validate one runtime redirect URI string."""
    if urlsplit(redirect_uri).fragment:
        raise ValueError(ERR_INVALID_REQUEST)


def validate_pkce_method(code_challenge_method: str | None) -> None:
    """Validate PKCE challenge method."""
    if code_challenge_method != "S256":
        raise ValueError(ERR_INVALID_REQUEST)


def validate_pkce_challenge(code_challenge: str) -> None:
    """Validate runtime PKCE code challenge syntax."""
    if PKCE_CHALLENGE_PATTERN.fullmatch(code_challenge) is None:
        raise ValueError(ERR_INVALID_REQUEST)
