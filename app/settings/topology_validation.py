"""Feature-topology validation for canonical server settings."""

from __future__ import annotations

from typing import TYPE_CHECKING


if TYPE_CHECKING:
    from app.settings.root import Settings


def validate_feature_topology(settings: Settings) -> None:
    """Reject incompatible authentication and presentation capabilities."""
    if not settings.browser_session.enabled:
        if settings.oauth2.oidc_enabled:
            msg = "OpenID Connect support requires browser sessions."
            raise ValueError(msg)
        if settings.oauth2.authorization_code_enabled:
            msg = "OAuth2 authorization code support requires browser sessions."
            raise ValueError(msg)
        if settings.oauth2.device_code_enabled:
            msg = "OAuth2 device code support requires browser sessions."
            raise ValueError(msg)
        if settings.identity_workflow.registration_enabled:
            msg = (
                "Self-registration requires browser sessions. Disable "
                "identity_workflow.registration_enabled for a machine-only server."
            )
            raise ValueError(msg)
    if (
        settings.oauth2.device_code_enabled
        and settings.ui.oauth2_interaction_is_disabled
    ):
        msg = "OAuth2 device code support requires a built-in or external UI."
        raise ValueError(msg)
    if (
        settings.ui.identity_workflow_is_disabled
        and not settings.api.interactive_auth_routes_enabled
        and (settings.browser_session.enabled or settings.oauth2.refresh_token_enabled)
    ):
        msg = (
            "User identity workflows require built-in pages or interactive "
            "identity API routes while browser sessions or refresh tokens "
            "are enabled."
        )
        raise ValueError(msg)


def validate_authentication_available(settings: Settings) -> None:
    """Require at least one mechanism capable of authenticating a principal."""
    if settings.browser_session.enabled or settings.oauth2.has_enabled_grants:
        return
    msg = (
        "At least one authentication mechanism must remain enabled: "
        "browser sessions or an OAuth2 grant"
    )
    raise ValueError(msg)
