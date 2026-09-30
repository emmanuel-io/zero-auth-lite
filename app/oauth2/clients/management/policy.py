"""Registration policy for managed OAuth2 clients."""

from app.oauth2.clients.management.errors import (
    InvalidOAuth2ClientPayloadError,
    OAuth2ClientManagementErrorReason,
)
from app.oauth2.clients.redirect_uris import validate_redirect_uris
from app.oauth2.grants.types import OAuth2GrantType
from app.oauth2.settings import OAuth2Settings


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
        try:
            validate_redirect_uris(redirect_uris)
        except ValueError as exc:
            reason = exc.args[0] if exc.args else None
            if isinstance(reason, OAuth2ClientManagementErrorReason):
                raise InvalidOAuth2ClientPayloadError(reason) from exc
            raise InvalidOAuth2ClientPayloadError(diagnostic=str(exc)) from exc
        if not grant_types:
            raise InvalidOAuth2ClientPayloadError(
                OAuth2ClientManagementErrorReason.GRANT_TYPES_REQUIRED
            )
        if unknown_grants := set(grant_types) - ALLOWED_CLIENT_GRANT_TYPES:
            raise InvalidOAuth2ClientPayloadError(
                OAuth2ClientManagementErrorReason.UNSUPPORTED_GRANT_TYPES,
                context=tuple(sorted(unknown_grants)),
            )
        disabled_grants = {
            grant_type
            for grant_type in grant_types
            if not self.settings.is_grant_enabled(grant_type)
        }
        if disabled_grants:
            raise InvalidOAuth2ClientPayloadError(
                OAuth2ClientManagementErrorReason.DISABLED_GRANT_TYPES,
                context=tuple(sorted(disabled_grants)),
            )
        if "authorization_code" in grant_types and not redirect_uris:
            raise InvalidOAuth2ClientPayloadError(
                OAuth2ClientManagementErrorReason.REDIRECT_URIS_REQUIRED
            )
        if "client_credentials" in grant_types and not is_confidential:
            raise InvalidOAuth2ClientPayloadError(
                OAuth2ClientManagementErrorReason.CLIENT_CREDENTIALS_REQUIRES_CONFIDENTIAL_CLIENT
            )
        if "refresh_token" in grant_types and not {
            OAuth2GrantType.AUTHORIZATION_CODE,
            OAuth2GrantType.DEVICE_CODE,
        }.intersection(grant_types):
            raise InvalidOAuth2ClientPayloadError(
                OAuth2ClientManagementErrorReason.REFRESH_TOKEN_REQUIRES_ORIGINATING_FLOW
            )
        if (
            "authorization_code" in grant_types
            and not is_confidential
            and not requires_consent
        ):
            raise InvalidOAuth2ClientPayloadError(
                OAuth2ClientManagementErrorReason.PUBLIC_AUTHORIZATION_CLIENTS_REQUIRE_CONSENT
            )
