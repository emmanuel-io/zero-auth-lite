"""Pure validation helpers shared across OAuth2 flow services."""

from __future__ import annotations

import re
from typing import TYPE_CHECKING
from urllib.parse import urlsplit

from app.oauth2.error_codes import OAuth2ErrorCode, OAuth2ValidationReason
from app.oauth2.grants.types import OAuth2GrantType
from app.oauth2.oidc.claims import scope_includes_openid


if TYPE_CHECKING:
    from app.identity.dtos import IdentityUserDTO
    from app.oauth2.clients.dtos import OAuth2ClientReadDTO
    from app.oauth2.settings import OAuth2Settings


PKCE_CHALLENGE_PATTERN = re.compile(r"^[A-Za-z0-9_-]{43}$")


def normalize_scope(scope: str | None) -> str:
    """Return unique OAuth2 scope names in stable request order."""
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

    Raises:
        ValueError: If any requested scope is not allowed.
    """
    if set(requested_scope.split()) - set(allowed_scopes):
        raise ValueError(OAuth2ErrorCode.INVALID_SCOPE)


def validate_oidc_scope_enabled(
    *,
    requested_scope: str,
    oidc_enabled: bool,
) -> None:
    """Reject OIDC scopes when the optional OIDC layer is disabled.

    Raises:
        ValueError: If openid is requested while OIDC is disabled.
    """
    if scope_includes_openid(requested_scope) and not oidc_enabled:
        raise ValueError(OAuth2ErrorCode.INVALID_SCOPE)


def user_display_name(user: IdentityUserDTO) -> str | None:
    """Build an OIDC profile display name when name data is available."""
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
    return settings.is_grant_enabled(OAuth2GrantType.REFRESH_TOKEN) and (
        client is None or client_allows_grant(client, OAuth2GrantType.REFRESH_TOKEN)
    )


def normalize_user_code(user_code: str) -> str:
    """Return an uppercase device user code without spaces."""
    return user_code.strip().replace(" ", "").upper()


def reject_redirect_uri_fragment(redirect_uri: str) -> None:
    """Reject a runtime redirect URI carrying a fragment."""
    if urlsplit(redirect_uri).fragment:
        raise ValueError(OAuth2ValidationReason.INVALID_REDIRECT_URI)


def validate_pkce_method(code_challenge_method: str | None) -> None:
    """Validate PKCE challenge method."""
    if code_challenge_method != "S256":
        raise ValueError(OAuth2ErrorCode.INVALID_REQUEST)


def validate_pkce_challenge(code_challenge: str) -> None:
    """Validate runtime PKCE code challenge syntax."""
    if PKCE_CHALLENGE_PATTERN.fullmatch(code_challenge) is None:
        raise ValueError(OAuth2ErrorCode.INVALID_REQUEST)
