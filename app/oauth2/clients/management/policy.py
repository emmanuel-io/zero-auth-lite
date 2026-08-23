"""Registration policy for managed OAuth2 clients."""

from app.oauth2.clients.management.errors import (
    InvalidOAuth2ClientPayloadError,
)
from app.oauth2.settings import OAuth2GrantType, OAuth2Settings


ERR_GRANT_TYPES_REQUIRED = "grant_types_required"
ERR_CLIENT_SECRET_ROTATION_REQUIRED = "client_secret_rotation_required"  # noqa: S105
ERR_PUBLIC_CLIENT_HAS_NO_SECRET = "public_client_has_no_secret"  # noqa: S105
ERR_PUBLIC_AUTHORIZATION_CLIENTS_REQUIRE_CONSENT = (
    "public_authorization_clients_require_consent"
)
ERR_REDIRECT_URIS_REQUIRED = "redirect_uris_required"
ERR_UNSUPPORTED_GRANT_TYPES = "unsupported_grant_types"
ERR_DISABLED_GRANT_TYPES = "disabled_grant_types"
ERR_CLIENT_CREDENTIALS_REQUIRES_CONFIDENTIAL = (
    "client_credentials_requires_confidential_client"
)
ERR_REFRESH_REQUIRES_ORIGINATING_FLOW = "refresh_token_requires_originating_flow"

ALLOWED_CLIENT_GRANT_TYPES = frozenset(
    grant_type.value for grant_type in OAuth2GrantType
)


class OAuth2ClientPolicy:
    """Validate OAuth2 client registrations against server grant policy."""

    def __init__(self, settings: OAuth2Settings) -> None:
        """Initialize the policy from server-level OAuth2 settings."""
        self.settings = settings

    def validate(
        self,
        *,
        grant_types: list[str],
        redirect_uris: list[str],
        is_confidential: bool,
        requires_consent: bool,
    ) -> None:
        """Validate OAuth2 client grant and redirect settings."""
        if not grant_types:
            raise InvalidOAuth2ClientPayloadError(ERR_GRANT_TYPES_REQUIRED)
        if unknown_grants := set(grant_types) - ALLOWED_CLIENT_GRANT_TYPES:
            detail = f"{ERR_UNSUPPORTED_GRANT_TYPES}:{','.join(sorted(unknown_grants))}"
            raise InvalidOAuth2ClientPayloadError(detail)
        disabled_grants = {
            grant_type
            for grant_type in grant_types
            if not self.settings.is_grant_enabled(grant_type)
        }
        if disabled_grants:
            detail = f"{ERR_DISABLED_GRANT_TYPES}:{','.join(sorted(disabled_grants))}"
            raise InvalidOAuth2ClientPayloadError(detail)
        if "authorization_code" in grant_types and not redirect_uris:
            raise InvalidOAuth2ClientPayloadError(ERR_REDIRECT_URIS_REQUIRED)
        if "client_credentials" in grant_types and not is_confidential:
            raise InvalidOAuth2ClientPayloadError(
                ERR_CLIENT_CREDENTIALS_REQUIRES_CONFIDENTIAL
            )
        if "refresh_token" in grant_types and not {
            OAuth2GrantType.authorization_code,
            OAuth2GrantType.device_code,
        }.intersection(grant_types):
            raise InvalidOAuth2ClientPayloadError(ERR_REFRESH_REQUIRES_ORIGINATING_FLOW)
        if (
            "authorization_code" in grant_types
            and not is_confidential
            and not requires_consent
        ):
            raise InvalidOAuth2ClientPayloadError(
                ERR_PUBLIC_AUTHORIZATION_CLIENTS_REQUIRE_CONSENT
            )
