"""OpenAPI configuration for OAuth2 and OIDC protocol routes."""

from typing import Any

from fastapi import FastAPI

from app.core.openapi import (
    document_request_id_response_header,
    document_validation_error_response,
)
from app.oauth2.protocol_route import PROTOCOL_OPENAPI_MARKER
from app.oauth2.settings import OAuth2GrantType
from app.oauth2.specs import OAuth2Specs
from app.security.openapi import configure_application_api_security
from app.settings.root import Settings
from app.settings.state import get_settings_snapshot


NO_STORE_HEADERS = {
    "Cache-Control": {
        "description": "Prevents storage of sensitive OAuth2 responses.",
        "schema": {"type": "string", "const": "no-store"},
    },
    "Pragma": {
        "description": "Compatibility cache directive.",
        "schema": {"type": "string", "const": "no-cache"},
    },
}
LOCATION_HEADER = {
    "Location": {
        "description": "Validated client redirect URI carrying a code or OAuth2 error.",
        "schema": {"type": "string", "format": "uri"},
    }
}


def _token_grant_schemas() -> dict[str, dict[str, Any]]:
    """Return grant-specific form schemas FastAPI cannot infer from one route."""
    optional_client_fields = {
        "client_id": {"type": ["string", "null"]},
        "client_secret": {"type": ["string", "null"], "writeOnly": True},
    }
    return {
        "OAuth2AuthorizationCodeGrantForm": {
            "type": "object",
            "required": ["grant_type", "code", "redirect_uri", "code_verifier"],
            "properties": {
                "grant_type": {"type": "string", "const": "authorization_code"},
                "code": {"type": "string", "minLength": 1},
                "redirect_uri": {"type": "string", "format": "uri"},
                "code_verifier": {
                    "type": "string",
                    "minLength": OAuth2Specs.CODE_VERIFIER_LENGTH_MIN,
                    "maxLength": OAuth2Specs.CODE_VERIFIER_LENGTH_MAX,
                    "pattern": OAuth2Specs.CODE_VERIFIER_PATTERN,
                },
                **optional_client_fields,
            },
        },
        "OAuth2RefreshTokenGrantForm": {
            "type": "object",
            "required": ["grant_type", "refresh_token"],
            "properties": {
                "grant_type": {"type": "string", "const": "refresh_token"},
                "refresh_token": {"type": "string", "minLength": 1},
                "scope": {
                    "type": ["string", "null"],
                    "description": "Not supported; supplied scope is rejected.",
                },
                **optional_client_fields,
            },
        },
        "OAuth2ClientCredentialsGrantForm": {
            "type": "object",
            "required": ["grant_type"],
            "properties": {
                "grant_type": {"type": "string", "const": "client_credentials"},
                "scope": {"type": ["string", "null"]},
                **optional_client_fields,
            },
        },
        "OAuth2DeviceCodeGrantForm": {
            "type": "object",
            "required": ["grant_type", "device_code"],
            "properties": {
                "grant_type": {
                    "type": "string",
                    "const": "urn:ietf:params:oauth:grant-type:device_code",
                },
                "device_code": {"type": "string", "minLength": 1},
                **optional_client_fields,
            },
        },
    }


def _set_response_headers(operation: dict[str, Any], *status_codes: str) -> None:
    """Document no-store headers on selected responses."""
    responses = operation.get("responses", {})
    for status_code in status_codes:
        response = responses.get(status_code)
        if isinstance(response, dict):
            response["headers"] = NO_STORE_HEADERS


def _enabled_token_grant_schemas(settings: Settings) -> dict[str, dict[str, Any]]:
    """Return request schemas for grants enabled at startup."""
    schemas = _token_grant_schemas()
    schema_names = {
        OAuth2GrantType.authorization_code: "OAuth2AuthorizationCodeGrantForm",
        OAuth2GrantType.refresh_token: "OAuth2RefreshTokenGrantForm",
        OAuth2GrantType.client_credentials: "OAuth2ClientCredentialsGrantForm",
        OAuth2GrantType.device_code: "OAuth2DeviceCodeGrantForm",
    }
    return {
        name: schemas[name]
        for grant_type, name in schema_names.items()
        if settings.oauth2.is_grant_enabled(grant_type)
    }


def _configure_protocol_openapi(schema: dict[str, Any], settings: Settings) -> None:
    """Add protocol semantics that are conditional or response-oriented."""
    paths = schema.get("paths", {})
    components = schema.setdefault("components", {}).setdefault("schemas", {})
    grant_schemas = _enabled_token_grant_schemas(settings)
    components.update(grant_schemas)

    authorize_path = paths.get("/oauth2/authorize", {})
    for method in ("get", "post"):
        operation = authorize_path.get(method)
        if not isinstance(operation, dict):
            continue
        operation["responses"]["302"]["headers"] = LOCATION_HEADER
    authorize_get = authorize_path.get("get")
    if isinstance(authorize_get, dict):
        parameters = {
            parameter["name"]: parameter
            for parameter in authorize_get.get("parameters", [])
        }
        parameters["response_type"]["schema"].update({"const": "code"})
        parameters["code_challenge_method"]["schema"].update({"const": "S256"})
        parameters["code_challenge"]["schema"].update(
            {
                "minLength": OAuth2Specs.CODE_CHALLENGE_LENGTH_MIN,
                "maxLength": OAuth2Specs.CODE_CHALLENGE_LENGTH_MAX,
                "pattern": OAuth2Specs.CODE_CHALLENGE_PATTERN,
            }
        )

    token_operation = paths.get("/oauth2/token", {}).get("post")
    if isinstance(token_operation, dict):
        token_operation["security"] = [{"OAuth2ClientBasic": []}, {}]
        request_schema: dict[str, Any]
        if grant_schemas:
            request_schema = {
                "oneOf": [
                    {"$ref": f"#/components/schemas/{name}"} for name in grant_schemas
                ],
                "discriminator": {"propertyName": "grant_type"},
            }
        else:
            request_schema = {
                "not": {},
                "description": "No OAuth2 token grants are enabled.",
            }
        token_operation["requestBody"]["content"]["application/x-www-form-urlencoded"][
            "schema"
        ] = request_schema
        _set_response_headers(token_operation, "200", "400", "401")

    for path in ("/oauth2/revoke", "/oauth2/device_authorization"):
        operation = paths.get(path, {}).get("post")
        if isinstance(operation, dict):
            operation["security"] = [{"OAuth2ClientBasic": []}, {}]
            operation["requestBody"]["required"] = True
            _set_response_headers(operation, "200", "400", "401")

    revocation_operation = paths.get("/oauth2/revoke", {}).get("post")
    if isinstance(revocation_operation, dict):
        revocation_operation["responses"]["200"].pop("content", None)

    introspection_operation = paths.get("/oauth2/introspect", {}).get("post")
    if isinstance(introspection_operation, dict):
        introspection_operation["security"] = [{"OAuth2ClientBasic": []}]
        _set_response_headers(introspection_operation, "200", "400", "401")

    for method in ("get", "post"):
        userinfo_operation = paths.get("/oauth2/userinfo", {}).get(method)
        if not isinstance(userinfo_operation, dict):
            continue
        userinfo_operation["security"] = [{"HTTPBearer": []}]


def configure_oauth2_openapi(app: FastAPI) -> None:
    """Configure protocol and application-authentication OpenAPI contracts."""
    default_openapi = app.openapi

    def oauth2_openapi() -> dict[str, Any]:
        schema = default_openapi()
        paths = schema.get("paths", {})
        for path in paths.values():
            if not isinstance(path, dict):
                continue
            for operation in path.values():
                if not isinstance(operation, dict):
                    continue
                if operation.pop(PROTOCOL_OPENAPI_MARKER, False):
                    operation.get("responses", {}).pop("422", None)
                else:
                    document_validation_error_response(operation)
        settings = get_settings_snapshot(app)
        _configure_protocol_openapi(schema, settings)
        configure_application_api_security(schema, settings)
        document_request_id_response_header(schema)
        return schema

    app.openapi = oauth2_openapi  # type: ignore[method-assign]  # ty: ignore[invalid-assignment]
