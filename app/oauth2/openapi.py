"""OpenAPI configuration for OAuth2 and OIDC protocol routes."""

from typing import Any, cast

from app.http_paths import (
    OAUTH2_AUTHORIZE_DECISION_ENDPOINT,
    OAUTH2_AUTHORIZE_ENDPOINT,
    OAUTH2_DEVICE_AUTHORIZATION_ENDPOINT,
    OAUTH2_INTROSPECTION_ENDPOINT,
    OAUTH2_REVOCATION_ENDPOINT,
    OAUTH2_TOKEN_ENDPOINT,
    OAUTH2_USERINFO_ENDPOINT,
)
from app.oauth2.grants.types import OAuth2GrantType
from app.oauth2.protocol_route import PROTOCOL_OPENAPI_MARKER
from app.oauth2.specs import OAuth2Specs
from app.settings.root import Settings


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
AUTHORIZATION_REDIRECT_HEADERS = {**NO_STORE_HEADERS, **LOCATION_HEADER}


def _token_grant_schemas() -> dict[str, dict[str, Any]]:
    """Return grant-specific form schemas FastAPI cannot infer from one route."""
    optional_client_fields = {
        "client_id": {
            "type": ["string", "null"],
            "maxLength": OAuth2Specs.CLIENT_ID_LENGTH_MAX,
        },
        "client_secret": {
            "type": ["string", "null"],
            "maxLength": OAuth2Specs.PROTOCOL_VALUE_LENGTH_MAX,
            "writeOnly": True,
        },
    }
    return {
        "OAuth2AuthorizationCodeGrantForm": {
            "type": "object",
            "required": ["grant_type", "code", "redirect_uri", "code_verifier"],
            "properties": {
                "grant_type": {"type": "string", "const": "authorization_code"},
                "code": {
                    "type": "string",
                    "minLength": 1,
                    "maxLength": OAuth2Specs.PROTOCOL_VALUE_LENGTH_MAX,
                },
                "redirect_uri": {
                    "type": "string",
                    "format": "uri",
                    "maxLength": OAuth2Specs.REDIRECT_URI_LENGTH_MAX,
                },
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
                "refresh_token": {
                    "type": "string",
                    "minLength": 1,
                    "maxLength": OAuth2Specs.PROTOCOL_VALUE_LENGTH_MAX,
                },
                "scope": {
                    "type": ["string", "null"],
                    "maxLength": OAuth2Specs.SCOPE_LIST_LENGTH_MAX,
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
                "scope": {
                    "type": ["string", "null"],
                    "maxLength": OAuth2Specs.SCOPE_LIST_LENGTH_MAX,
                },
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
                "device_code": {
                    "type": "string",
                    "minLength": 1,
                    "maxLength": OAuth2Specs.PROTOCOL_VALUE_LENGTH_MAX,
                },
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


def _required_parameter_schema(
    operation: dict[str, Any], *, name: str
) -> dict[str, Any]:
    """Return one typed parameter schema or fail with a focused contract error."""
    for parameter in operation.get("parameters", []):
        if (
            isinstance(parameter, dict)
            and parameter.get("name") == name
            and isinstance(parameter.get("schema"), dict)
        ):
            return cast("dict[str, Any]", parameter["schema"])
    msg = f"OpenAPI operation is missing the typed {name!r} parameter."
    raise RuntimeError(msg)


def _enabled_token_grant_schemas(settings: Settings) -> dict[str, dict[str, Any]]:
    """Return request schemas for grants enabled at startup."""
    schemas = _token_grant_schemas()
    schema_names = {
        OAuth2GrantType.AUTHORIZATION_CODE: "OAuth2AuthorizationCodeGrantForm",
        OAuth2GrantType.REFRESH_TOKEN: "OAuth2RefreshTokenGrantForm",
        OAuth2GrantType.CLIENT_CREDENTIALS: "OAuth2ClientCredentialsGrantForm",
        OAuth2GrantType.DEVICE_CODE: "OAuth2DeviceCodeGrantForm",
    }
    return {
        name: schemas[name]
        for grant_type, name in schema_names.items()
        if settings.oauth2.is_grant_enabled(grant_type)
    }


def configure_oauth2_schema(  # noqa: C901, PLR0912
    schema: dict[str, Any], settings: Settings
) -> None:
    """Add protocol semantics that are conditional or response-oriented."""
    paths = schema.get("paths", {})
    components = schema.setdefault("components", {}).setdefault("schemas", {})
    grant_schemas = _enabled_token_grant_schemas(settings)
    components.update(grant_schemas)

    authorize_path = paths.get(OAUTH2_AUTHORIZE_ENDPOINT, {})
    for method in ("get", "post"):
        operation = authorize_path.get(method)
        if not isinstance(operation, dict):
            continue
        for status_code in ("302", "303"):
            operation["responses"][status_code]["headers"] = (
                AUTHORIZATION_REDIRECT_HEADERS
            )
    authorize_decision = paths.get(OAUTH2_AUTHORIZE_DECISION_ENDPOINT, {}).get("post")
    if isinstance(authorize_decision, dict):
        authorize_decision["responses"]["302"]["headers"] = (
            AUTHORIZATION_REDIRECT_HEADERS
        )
    authorize_get = authorize_path.get("get")
    if isinstance(authorize_get, dict):
        _required_parameter_schema(authorize_get, name="response_type").update(
            {"const": "code"}
        )
        _required_parameter_schema(authorize_get, name="code_challenge_method").update(
            {"const": "S256"}
        )
        _required_parameter_schema(authorize_get, name="code_challenge").update(
            {
                "minLength": OAuth2Specs.CODE_CHALLENGE_LENGTH_MIN,
                "maxLength": OAuth2Specs.CODE_CHALLENGE_LENGTH_MAX,
                "pattern": OAuth2Specs.CODE_CHALLENGE_PATTERN,
            }
        )

    token_operation = paths.get(OAUTH2_TOKEN_ENDPOINT, {}).get("post")
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

    for path in (OAUTH2_REVOCATION_ENDPOINT, OAUTH2_DEVICE_AUTHORIZATION_ENDPOINT):
        operation = paths.get(path, {}).get("post")
        if isinstance(operation, dict):
            operation["security"] = [{"OAuth2ClientBasic": []}, {}]
            operation["requestBody"]["required"] = True
            _set_response_headers(operation, "200", "400", "401")

    revocation_operation = paths.get(OAUTH2_REVOCATION_ENDPOINT, {}).get("post")
    if isinstance(revocation_operation, dict):
        revocation_operation["responses"]["200"].pop("content", None)

    introspection_operation = paths.get(OAUTH2_INTROSPECTION_ENDPOINT, {}).get("post")
    if isinstance(introspection_operation, dict):
        # The empty alternative represents confidential credentials carried by
        # the typed form body instead of the HTTP Basic security scheme.
        introspection_operation["security"] = [{"OAuth2ClientBasic": []}, {}]
        _set_response_headers(introspection_operation, "200", "400", "401")

    for method in ("get", "post"):
        userinfo_operation = paths.get(OAUTH2_USERINFO_ENDPOINT, {}).get(method)
        if not isinstance(userinfo_operation, dict):
            continue
        userinfo_operation["security"] = [{"HTTPBearer": []}]


def configure_protocol_operation(operation: dict[str, Any]) -> bool:
    """Apply protocol error semantics and report whether they were selected."""
    if not operation.pop(PROTOCOL_OPENAPI_MARKER, False):
        return False
    responses = operation.setdefault("responses", {})
    responses.pop("422", None)
    responses.setdefault(
        "500",
        {
            "description": "Unexpected server failure using the OAuth2 error contract.",
            "content": {
                "application/json": {
                    "schema": {"$ref": "#/components/schemas/OAuth2ErrorResponse"}
                }
            },
            "headers": NO_STORE_HEADERS,
        },
    )
    return True
