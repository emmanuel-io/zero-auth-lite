"""Browser-presentation URL validation for canonical server settings."""

from __future__ import annotations

from typing import TYPE_CHECKING
from urllib.parse import urlsplit

from app.settings.ui import (
    BUILTIN_AUTHORIZATION_CONSENT_PATH,
    BUILTIN_AUTHORIZATION_INTERACTION_PATH,
    BUILTIN_DEVICE_INTERACTION_PATH,
    BUILTIN_INVITATION_PATH,
    BUILTIN_LOGIN_PATH,
    BUILTIN_LOGOUT_PATH,
    BUILTIN_PASSWORD_RESET_PATH,
    BUILTIN_VERIFICATION_PATH,
)


if TYPE_CHECKING:
    from app.settings.root import Settings


def validate_ui_urls(settings: Settings) -> None:
    """Require browser destinations matching their active presentation modes."""
    builtin_origin = settings.browser_session.csrf.public_origin
    interactive_oauth2_enabled = (
        settings.oauth2.authorization_code_enabled
        or settings.oauth2.device_code_enabled
    )
    external_transport_required = (
        settings.ui.identity_workflow_is_external
        or settings.ui.management_authentication_is_external
        or (settings.ui.oauth2_interaction_is_external and interactive_oauth2_enabled)
    )
    if external_transport_required and not settings.api.interactive_auth_routes_enabled:
        msg = (
            "External browser presentation requires the interactive "
            "authentication API routes."
        )
        raise ValueError(msg)

    if (
        settings.ui.management_authentication_is_builtin
        and settings.browser_session.enabled
    ):
        _require_builtin_destination(
            "ui.urls.login", settings.ui.urls.login, BUILTIN_LOGIN_PATH
        )
        _require_builtin_destination(
            "ui.urls.logout", settings.ui.urls.logout, BUILTIN_LOGOUT_PATH
        )
    elif (
        settings.ui.management_authentication_is_external
        and settings.browser_session.enabled
    ):
        _require_absolute_http_url("ui.urls.login", settings.ui.urls.login)
        _require_absolute_http_url("ui.urls.logout", settings.ui.urls.logout)

    if settings.ui.identity_workflow_is_builtin:
        _require_builtin_absolute_destination(
            "ui.urls.verification",
            settings.ui.urls.verification,
            BUILTIN_VERIFICATION_PATH,
            origin=builtin_origin,
        )
        _require_builtin_absolute_destination(
            "ui.urls.password_reset",
            settings.ui.urls.password_reset,
            BUILTIN_PASSWORD_RESET_PATH,
            origin=builtin_origin,
        )
        _require_builtin_absolute_destination(
            "ui.urls.invitation",
            settings.ui.urls.invitation,
            BUILTIN_INVITATION_PATH,
            origin=builtin_origin,
        )
    elif settings.ui.identity_workflow_is_external or (
        settings.ui.identity_workflow_is_disabled
        and settings.api.interactive_auth_routes_enabled
    ):
        _require_absolute_http_url(
            "ui.urls.verification", settings.ui.urls.verification
        )
        _require_absolute_http_url(
            "ui.urls.password_reset", settings.ui.urls.password_reset
        )
        _require_absolute_http_url("ui.urls.invitation", settings.ui.urls.invitation)

    if settings.ui.oauth2_interaction_is_builtin:
        if settings.oauth2.authorization_code_enabled:
            _require_builtin_destination(
                "ui.urls.authorization_interaction",
                settings.ui.urls.authorization_interaction,
                BUILTIN_AUTHORIZATION_INTERACTION_PATH,
            )
            _require_builtin_destination(
                "ui.urls.authorization_consent",
                settings.ui.urls.authorization_consent,
                BUILTIN_AUTHORIZATION_CONSENT_PATH,
            )
        if settings.oauth2.device_code_enabled:
            _require_builtin_absolute_destination(
                "ui.urls.device_interaction",
                settings.ui.urls.device_interaction,
                BUILTIN_DEVICE_INTERACTION_PATH,
                origin=builtin_origin,
            )
    elif settings.ui.oauth2_interaction_is_external:
        if settings.oauth2.authorization_code_enabled:
            _require_absolute_http_url(
                "ui.urls.authorization_interaction",
                settings.ui.urls.authorization_interaction,
            )
        if settings.oauth2.device_code_enabled:
            _require_absolute_http_url(
                "ui.urls.device_interaction", settings.ui.urls.device_interaction
            )


def _require_absolute_http_url(name: str, value: str) -> None:
    """Require an absolute HTTP(S) workflow or navigation destination."""
    parsed = urlsplit(value)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        msg = f"An absolute HTTP(S) URL is required in {name}."
        raise ValueError(msg)


def _require_builtin_destination(name: str, value: str, path: str) -> None:
    """Require the canonical route used by a built-in UI."""
    parsed = urlsplit(value)
    if parsed.scheme or parsed.netloc or value != path:
        msg = f"Built-in presentation requires {name} to target {path}."
        raise ValueError(msg)


def _require_builtin_absolute_destination(
    name: str, value: str, path: str, *, origin: str | None
) -> None:
    """Require a built-in page on the configured public authentication origin."""
    if origin is None:
        msg = f"Built-in presentation requires a public origin for {name}."
        raise ValueError(msg)
    parsed = urlsplit(value)
    if f"{parsed.scheme}://{parsed.netloc}" != origin or parsed.path != path:
        msg = (
            f"Built-in presentation requires {name} to use "
            f"browser_session.csrf.public_origin ({origin}) and target {path}."
        )
        raise ValueError(msg)
