"""Shared OpenAPI tag names and metadata for the canonical server."""

from app.settings.root import Settings
from app.web.settings import AuthenticationUIMode


AUTHENTICATION_V1_TAG = "Authentication v1"
BUILTIN_AUTH_UI_TAG = "Built-in Authentication UI"
HEALTH_TAG = "Health"
IDENTITY_PROFILE_V1_TAG = "Identity Profile v1"
OIDC_TAG = "OpenID Connect"
OAUTH2_AUTHORIZATION_CODE_FLOW_TAG = "OAuth2 Authorization Code Flow"
OAUTH2_DEVICE_FLOW_TAG = "OAuth2 Device Flow"
OAUTH2_DISCOVERY_TAG = "OAuth2 Discovery"
OAUTH2_JWKS_TAG = "OAuth2 JWKS"
OAUTH2_TOKEN_PROTOCOL_TAG = "OAuth2 Token Protocol"  # noqa: S105
SERVER_ADMINISTRATION_V1_TAG = "Server Administration v1"
SESSION_TAG = "Session v1"
ORGANIZATION_ADMINISTRATION_V1_TAG = "Organization Administration v1"


def create_openapi_tags(settings: Settings) -> list[dict[str, str]]:
    """Build all openapi tags for the current settings."""
    openapi_tags = [
        {
            "name": HEALTH_TAG,
            "description": "Minimal health and smoke-check endpoints.",
        }
    ]
    if settings.session.enabled:
        openapi_tags.append(
            {
                "name": SESSION_TAG,
                "description": (
                    "Browser-session transport endpoints under "
                    "`/api/v1/sessions` and "
                    "operator-managed browser-session administration endpoints."
                ),
            }
        )
    if settings.ui.authentication == AuthenticationUIMode.BUILTIN:
        openapi_tags.append(
            {
                "name": BUILTIN_AUTH_UI_TAG,
                "description": (
                    "Server-rendered authentication and browser-session forms mounted "
                    "when `ui.authentication=builtin`."
                ),
            }
        )

    openapi_tags.extend(
        [
            {
                "name": AUTHENTICATION_V1_TAG,
                "description": (
                    "Versioned application-owned authentication workflows such as "
                    "registration, email verification, password reset, and invite "
                    "acceptance."
                ),
            },
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
                "name": SERVER_ADMINISTRATION_V1_TAG,
                "description": (
                    "Server administration endpoints under `/api/v1/admin`. "
                    "These endpoints are not accessible to standard users or "
                    "organization administrators."
                ),
            },
            {
                "name": OAUTH2_AUTHORIZATION_CODE_FLOW_TAG,
                "description": "OAuth2 authorization and consent endpoints.",
            },
            {
                "name": OAUTH2_TOKEN_PROTOCOL_TAG,
                "description": (
                    "OAuth2 token issuance, revocation, and introspection endpoints."
                ),
            },
            {
                "name": OAUTH2_DEVICE_FLOW_TAG,
                "description": (
                    "OAuth2 device authorization and verification endpoints."
                ),
            },
            {
                "name": OAUTH2_DISCOVERY_TAG,
                "description": "OAuth2 and authorization-server metadata endpoints.",
            },
            {
                "name": OAUTH2_JWKS_TAG,
                "description": "JSON Web Key Set endpoints for public signing keys.",
            },
            {
                "name": OIDC_TAG,
                "description": (
                    "OpenID Connect discovery and user information endpoints."
                ),
            },
        ]
    )
    return openapi_tags
