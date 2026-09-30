"""Shared OpenAPI tag names and metadata for the canonical server."""

from app.settings.root import Settings
from app.web.composition import authentication_ui_enabled, management_ui_enabled


ACCOUNT_UI_TAG = "Account UI"
AUTHENTICATION_V1_TAG = "Authentication v1"
BUILTIN_AUTH_UI_TAG = "Built-in Authentication UI"
HEALTH_TAG = "Health"
IDENTITY_PROFILE_V1_TAG = "Identity Profile v1"
MANAGEMENT_UI_TAG = "Management UI"
OIDC_TAG = "OpenID Connect"
OAUTH2_AUTHORIZATION_CODE_FLOW_TAG = "OAuth2 Authorization Code Flow"
OAUTH2_DEVICE_FLOW_TAG = "OAuth2 Device Flow"
OAUTH2_DISCOVERY_TAG = "OAuth2 Discovery"
OAUTH2_JWKS_TAG = "OAuth2 JWKS"
OAUTH2_INTERACTION_V1_TAG = "OAuth2 Interaction v1"
OAUTH2_TOKEN_PROTOCOL_TAG = "OAuth2 Token Protocol"  # noqa: S105
OPERATOR_UI_TAG = "Operator UI"
SERVER_CONTROL_PLANE_V1_TAG = "Server Control Plane v1"
SESSION_TAG = "Session v1"
ORGANIZATION_ADMINISTRATION_UI_TAG = "Organization Administration UI"
ORGANIZATION_ADMINISTRATION_V1_TAG = "Organization Administration v1"


def _management_ui_tags(settings: Settings) -> list[dict[str, str]]:
    """Build metadata for the mounted session-backed HTML routes."""
    if not management_ui_enabled(settings):
        return []

    tags = [
        {
            "name": MANAGEMENT_UI_TAG,
            "description": (
                "Session-backed management dashboard rendered with the "
                "HTMX-enhanced management shell."
            ),
        },
        {
            "name": ACCOUNT_UI_TAG,
            "description": (
                "Session-backed current-user account pages rendered with the "
                "HTMX-enhanced management shell."
            ),
        },
    ]
    if settings.ui.organization_admin_enabled:
        tags.append(
            {
                "name": ORGANIZATION_ADMINISTRATION_UI_TAG,
                "description": (
                    "Session-backed organization administration pages rendered "
                    "with the HTMX-enhanced management shell."
                ),
            }
        )
    if settings.ui.operator_enabled:
        tags.append(
            {
                "name": OPERATOR_UI_TAG,
                "description": (
                    "Session-backed server-operator pages rendered with the "
                    "HTMX-enhanced management shell."
                ),
            }
        )
    return tags


def create_openapi_tags(settings: Settings) -> list[dict[str, str]]:
    """Build OpenAPI tag metadata for the routes mounted by the settings."""
    openapi_tags = [
        {
            "name": HEALTH_TAG,
            "description": "Operational process-liveness and SQLite-readiness checks.",
        }
    ]
    if (
        settings.browser_session.enabled
        and settings.api.interactive_auth_routes_enabled
    ):
        openapi_tags.append(
            {
                "name": SESSION_TAG,
                "description": (
                    "Browser-session authentication transport endpoints under "
                    "`/api/v1/sessions`."
                ),
            }
        )

    if settings.api.interactive_auth_routes_enabled:
        openapi_tags.append(
            {
                "name": AUTHENTICATION_V1_TAG,
                "description": (
                    "Versioned application-owned authentication workflows such as "
                    "registration, email verification, password reset, and invite "
                    "acceptance."
                ),
            }
        )
    if (
        settings.api.interactive_auth_routes_enabled
        and settings.ui.oauth2_interaction_is_external
        and (
            settings.oauth2.authorization_code_enabled
            or settings.oauth2.device_code_enabled
        )
    ):
        openapi_tags.append(
            {
                "name": OAUTH2_INTERACTION_V1_TAG,
                "description": (
                    "Session-bound JSON continuation endpoints for an external "
                    "OAuth2 interaction frontend."
                ),
            }
        )

    openapi_tags.extend(
        [
            {
                "name": IDENTITY_PROFILE_V1_TAG,
                "description": (
                    "Self-service current-user resources under `/api/v1/me`, including "
                    "identity profile management."
                ),
            },
            {
                "name": ORGANIZATION_ADMINISTRATION_V1_TAG,
                "description": (
                    "Organization-scoped administration and current-organization "
                    "resources under `/api/v1/organization`."
                ),
            },
            {
                "name": SERVER_CONTROL_PLANE_V1_TAG,
                "description": (
                    "Server-wide control-plane endpoints under `/api/v1/server`. "
                    "Most require a server operator; explicit machine operations "
                    "document their client-credentials policy on the route."
                ),
            },
        ]
    )
    if settings.oauth2.authorization_code_enabled:
        openapi_tags.append(
            {
                "name": OAUTH2_AUTHORIZATION_CODE_FLOW_TAG,
                "description": "OAuth2 authorization and consent endpoints.",
            }
        )
    if settings.oauth2.has_enabled_grants:
        openapi_tags.append(
            {
                "name": OAUTH2_TOKEN_PROTOCOL_TAG,
                "description": (
                    "OAuth2 token issuance, revocation, and introspection endpoints."
                ),
            }
        )
    if settings.oauth2.device_code_enabled:
        openapi_tags.append(
            {
                "name": OAUTH2_DEVICE_FLOW_TAG,
                "description": (
                    "OAuth2 device authorization and verification endpoints."
                ),
            }
        )
    if settings.oauth2.protocol_enabled:
        openapi_tags.append(
            {
                "name": OAUTH2_DISCOVERY_TAG,
                "description": "OAuth2 and authorization-server metadata endpoints.",
            }
        )
    if settings.oauth2.jwks_enabled:
        openapi_tags.append(
            {
                "name": OAUTH2_JWKS_TAG,
                "description": "JSON Web Key Set endpoints for public signing keys.",
            }
        )
    if settings.oauth2.oidc_enabled:
        openapi_tags.append(
            {
                "name": OIDC_TAG,
                "description": (
                    "OpenID Connect discovery and user information endpoints."
                ),
            }
        )

    has_authentication_ui = authentication_ui_enabled(settings)
    if has_authentication_ui:
        openapi_tags.append(
            {
                "name": BUILTIN_AUTH_UI_TAG,
                "description": (
                    "Server-rendered authentication and browser-session forms mounted "
                    "for configured built-in authentication or OAuth2 interaction."
                ),
            }
        )

    openapi_tags.extend(_management_ui_tags(settings))

    return openapi_tags
