"""Predicates for composing Zero Auth Lite browser surfaces."""

from app.settings.root import Settings


def builtin_identity_workflows_enabled(settings: Settings) -> bool:
    """Return whether server-rendered identity workflow forms are mounted."""
    return settings.ui.identity_workflow_is_builtin


def builtin_management_authentication_enabled(settings: Settings) -> bool:
    """Return whether management uses the built-in login and logout pages."""
    return (
        settings.browser_session.enabled
        and settings.ui.management_authentication_is_builtin
    )


def builtin_oauth2_interaction_enabled(settings: Settings) -> bool:
    """Return whether an enabled interactive grant uses built-in pages."""
    return settings.ui.oauth2_interaction_is_builtin and (
        settings.oauth2.authorization_code_enabled
        or settings.oauth2.device_code_enabled
    )


def builtin_login_enabled(settings: Settings) -> bool:
    """Return whether any configured browser surface needs the built-in login."""
    return settings.browser_session.enabled and (
        builtin_management_authentication_enabled(settings)
        or builtin_oauth2_interaction_enabled(settings)
    )


def builtin_landing_enabled(settings: Settings) -> bool:
    """Return whether the built-in server entry point is mounted."""
    return builtin_identity_workflows_enabled(
        settings
    ) or builtin_management_authentication_enabled(settings)


def authentication_ui_enabled(settings: Settings) -> bool:
    """Return whether any authentication or OAuth2 interaction page is mounted."""
    return (
        builtin_landing_enabled(settings)
        or builtin_login_enabled(settings)
        or builtin_oauth2_interaction_enabled(settings)
    )


def management_ui_enabled(settings: Settings) -> bool:
    """Return whether the session-backed management surface is mounted."""
    return settings.browser_session.enabled
