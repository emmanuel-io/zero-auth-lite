"""OpenAPI contract tests for typed OAuth2 protocol requests."""

from typing import Any, cast

import pytest
from app.api.schemas import DEFAULT_PAGE_LIMIT_MAX
from app.browser_sessions.enums import CSRFPattern
from app.browser_sessions.settings import BrowserSessionSettings, CSRFSettings
from app.identity.users.specs import UserSpecs
from app.main import create_app
from app.oauth2.settings import OAuth2Settings
from app.oauth2.specs import OAuth2Specs
from app.password.validation import MAX_PASSWORD_LENGTH, MIN_PASSWORD_LENGTH
from app.settings.identity_workflow import IdentityWorkflowSettings
from app.settings.root import Settings
from app.settings.ui import (
    IdentityWorkflowUIMode,
    ManagementAuthenticationMode,
    OAuth2InteractionUIMode,
    UISettings,
)
from fastapi import FastAPI
from fastapi.openapi.models import OpenAPI

from tests.identifiers import UUID4_PATTERN


ORGANIZATION_ID_PATTERN = UUID4_PATTERN
USER_ID_PATTERN = UUID4_PATTERN
OAUTH2_SESSION_ID_PATTERN = UUID4_PATTERN


pytestmark = pytest.mark.unit
EXTERNAL_LOGIN_URL = "https://frontend.test/login"


@pytest.fixture(scope="module")
def app() -> FastAPI:
    """Build the schema without starting database-backed application lifespan."""
    return create_app(
        Settings(
            browser_session=BrowserSessionSettings(),
            ui=UISettings(
                identity_workflow_mode=IdentityWorkflowUIMode.EXTERNAL,
                management_authentication=ManagementAuthenticationMode.EXTERNAL,
                urls={
                    "login": EXTERNAL_LOGIN_URL,
                    "logout": "https://frontend.test/logout",
                },
            ),
        )
    )


@pytest.fixture(scope="module")
def sessionless_app() -> FastAPI:
    """Build OpenAPI for a machine-to-machine OAuth2 deployment."""
    return create_app(
        Settings(
            browser_session=BrowserSessionSettings(enabled=False),
            identity_workflow=IdentityWorkflowSettings(registration_enabled=False),
            ui=UISettings(
                oauth2_interaction=OAuth2InteractionUIMode.DISABLED,
            ),
            oauth2=OAuth2Settings().model_copy(
                update={
                    "authorization_code_enabled": False,
                    "refresh_token_enabled": False,
                    "device_code_enabled": False,
                    "oidc_enabled": False,
                }
            ),
        )
    )


def _operation(app: FastAPI, path: str, method: str) -> dict[str, Any]:
    """Return one generated OpenAPI operation."""
    return cast("dict[str, Any]", app.openapi()["paths"][path][method])


def _form_schema(app: FastAPI, path: str) -> dict[str, Any]:
    """Resolve one generated form request schema."""
    schema = app.openapi()
    form = schema["paths"][path]["post"]["requestBody"]["content"][
        "application/x-www-form-urlencoded"
    ]["schema"]
    reference = form.get("$ref")
    if reference is None:
        return cast("dict[str, Any]", form)
    return cast(
        "dict[str, Any]",
        schema["components"]["schemas"][reference.rsplit("/", 1)[1]],
    )


def test_openapi_exposes_membership_roles(
    app: FastAPI,
) -> None:
    """Expose organization membership roles."""
    schemas = app.openapi()["components"]["schemas"]

    assert "role" in schemas["OrganizationUserResponse"]["properties"]


def test_openapi_exposes_canonical_oauth2_error_codes(app: FastAPI) -> None:
    """Generate the OAuth2 error schema from the shared public vocabulary."""
    assert app.openapi()["components"]["schemas"]["OAuth2ErrorCode"]["enum"] == [
        "invalid_request",
        "invalid_client",
        "invalid_grant",
        "unauthorized_client",
        "unsupported_grant_type",
        "invalid_scope",
        "access_denied",
        "authorization_pending",
        "slow_down",
        "expired_token",
        "unsupported_token_type",
        "unsupported_response_type",
        "server_error",
        "temporarily_unavailable",
        "invalid_token",
        "insufficient_scope",
    ]


def test_authorization_openapi_separates_requests_and_decisions(
    app: FastAPI,
) -> None:
    """Expose typed GET/POST requests and a separate consent decision form."""
    get_operation = _operation(app, "/oauth2/authorize", "get")
    parameters = {item["name"]: item for item in get_operation["parameters"]}

    assert set(parameters) == {
        "response_type",
        "client_id",
        "redirect_uri",
        "scope",
        "state",
        "code_challenge",
        "code_challenge_method",
        "nonce",
    }
    assert parameters["response_type"]["schema"]["const"] == "code"
    assert parameters["code_challenge_method"]["schema"]["const"] == "S256"
    assert (
        parameters["code_challenge"]["schema"]["minLength"]
        == OAuth2Specs.CODE_CHALLENGE_LENGTH_MIN
    )
    assert (
        parameters["code_challenge"]["schema"]["maxLength"]
        == OAuth2Specs.CODE_CHALLENGE_LENGTH_MAX
    )
    assert (
        parameters["state"]["schema"]["anyOf"][0]["maxLength"]
        == OAuth2Specs.STATE_LENGTH_MAX
    )
    assert (
        parameters["nonce"]["schema"]["anyOf"][0]["maxLength"]
        == OAuth2Specs.NONCE_LENGTH_MAX
    )
    request_form = _form_schema(app, "/oauth2/authorize")
    assert set(request_form["properties"]) == {
        "response_type",
        "client_id",
        "redirect_uri",
        "scope",
        "state",
        "code_challenge",
        "code_challenge_method",
        "nonce",
    }
    decision_form = _form_schema(app, "/oauth2/authorize/decision")
    assert set(decision_form["properties"]) == {
        "transaction_id",
        "decision",
        "csrf_token",
    }
    assert set(decision_form["required"]) == {
        "transaction_id",
        "decision",
    }
    assert "422" not in get_operation["responses"]
    assert "422" not in _operation(app, "/oauth2/authorize", "post")["responses"]
    assert (
        "422" not in _operation(app, "/oauth2/authorize/decision", "post")["responses"]
    )
    for method in ("get", "post"):
        operation = _operation(app, "/oauth2/authorize", method)
        assert "200" not in operation["responses"]
        for status_code in ("302", "303"):
            headers = operation["responses"][status_code]["headers"]
            assert "Location" in headers
            assert headers["Cache-Control"]["schema"]["const"] == "no-store"
            assert headers["Pragma"]["schema"]["const"] == "no-cache"
    decision_operation = _operation(app, "/oauth2/authorize/decision", "post")
    assert "200" not in decision_operation["responses"]
    assert "Location" in decision_operation["responses"]["302"]["headers"]


def test_external_oauth2_interaction_openapi_contract() -> None:
    """Expose typed JSON interactions with session and CSRF security."""
    external_app = create_app(
        Settings(
            ui=UISettings(
                identity_workflow_mode=IdentityWorkflowUIMode.EXTERNAL,
                oauth2_interaction=OAuth2InteractionUIMode.EXTERNAL,
                urls={
                    "authorization_interaction": (
                        "https://frontend.example/oauth2/interaction"
                    ),
                    "device_interaction": (
                        "https://frontend.example/oauth2/interaction"
                    ),
                },
            ),
        )
    )
    schema = external_app.openapi()
    interaction_operations = {
        "/api/v1/oauth2/authorization-interactions/{transaction_id}": "post",
        "/api/v1/oauth2/authorization-interactions/{transaction_id}/decision": "post",
        "/api/v1/oauth2/device-interactions/{user_code}": "get",
        "/api/v1/oauth2/device-interactions/{user_code}/decision": "post",
    }

    assert interaction_operations.keys() <= schema["paths"].keys()
    for path, method in interaction_operations.items():
        operation = schema["paths"][path][method]
        expected_security: dict[str, list[str]] = {"APIKeyCookie": []}
        if method == "post":
            expected_security["SessionCSRFHeader"] = []
        assert operation["security"] == [expected_security]
        assert "400" in operation["responses"]
        assert "401" in operation["responses"]
        if method == "post":
            assert "403" in operation["responses"]
    authorization_path = schema["paths"][
        "/api/v1/oauth2/authorization-interactions/{transaction_id}"
    ]
    assert "get" not in authorization_path
    decision_schema = schema["components"]["schemas"][
        "OAuth2InteractionDecisionRequest"
    ]
    assert decision_schema["properties"]["decision"]["enum"] == [
        "approve",
        "deny",
    ]


def test_token_protocol_openapi_uses_forms_and_basic_auth(app: FastAPI) -> None:
    """Describe supported grants and token-management forms without query secrets."""
    token_schema = _form_schema(app, "/oauth2/token")
    assert token_schema["discriminator"]["propertyName"] == "grant_type"
    grant_forms = {item["$ref"].rsplit("/", 1)[1] for item in token_schema["oneOf"]}
    assert grant_forms == {
        "OAuth2AuthorizationCodeGrantForm",
        "OAuth2RefreshTokenGrantForm",
        "OAuth2ClientCredentialsGrantForm",
        "OAuth2DeviceCodeGrantForm",
    }
    schemas = app.openapi()["components"]["schemas"]
    grant_types = {
        schemas[name]["properties"]["grant_type"]["const"] for name in grant_forms
    }
    assert "password" not in grant_types
    verifier = schemas["OAuth2AuthorizationCodeGrantForm"]["properties"][
        "code_verifier"
    ]
    assert verifier["minLength"] == OAuth2Specs.CODE_VERIFIER_LENGTH_MIN
    assert verifier["maxLength"] == OAuth2Specs.CODE_VERIFIER_LENGTH_MAX

    authorization_code = schemas["OAuth2AuthorizationCodeGrantForm"]["properties"]
    refresh = schemas["OAuth2RefreshTokenGrantForm"]["properties"]
    client_credentials = schemas["OAuth2ClientCredentialsGrantForm"]["properties"]
    device = schemas["OAuth2DeviceCodeGrantForm"]["properties"]
    assert authorization_code["code"]["maxLength"] == (
        OAuth2Specs.PROTOCOL_VALUE_LENGTH_MAX
    )
    assert authorization_code["redirect_uri"]["maxLength"] == (
        OAuth2Specs.REDIRECT_URI_LENGTH_MAX
    )
    assert refresh["refresh_token"]["maxLength"] == (
        OAuth2Specs.PROTOCOL_VALUE_LENGTH_MAX
    )
    assert refresh["scope"]["maxLength"] == OAuth2Specs.SCOPE_LIST_LENGTH_MAX
    assert client_credentials["scope"]["maxLength"] == (
        OAuth2Specs.SCOPE_LIST_LENGTH_MAX
    )
    assert device["device_code"]["maxLength"] == (OAuth2Specs.PROTOCOL_VALUE_LENGTH_MAX)
    for form in grant_forms:
        properties = schemas[form]["properties"]
        assert properties["client_id"]["maxLength"] == (
            OAuth2Specs.CLIENT_ID_LENGTH_MAX
        )
        assert properties["client_secret"]["maxLength"] == (
            OAuth2Specs.PROTOCOL_VALUE_LENGTH_MAX
        )

    expected_token_form = {"token", "token_type_hint", "client_id", "client_secret"}
    assert set(_form_schema(app, "/oauth2/revoke")["properties"]) == expected_token_form
    assert (
        set(_form_schema(app, "/oauth2/introspect")["properties"])
        == expected_token_form
    )
    for path in ("/oauth2/token", "/oauth2/revoke", "/oauth2/device_authorization"):
        operation = _operation(app, path, "post")
        assert operation["security"] == [{"OAuth2ClientBasic": []}, {}]
        assert not operation.get("parameters")
        assert "422" not in operation["responses"]
        server_error = operation["responses"]["500"]
        assert server_error["content"]["application/json"]["schema"] == {
            "$ref": "#/components/schemas/OAuth2ErrorResponse"
        }
        assert server_error["headers"]["Cache-Control"]["schema"]["const"] == (
            "no-store"
        )
    introspection = _operation(app, "/oauth2/introspect", "post")
    assert introspection["security"] == [{"OAuth2ClientBasic": []}, {}]
    assert "422" not in introspection["responses"]
    for path in ("/oauth2/revoke", "/oauth2/introspect"):
        hint = _form_schema(app, path)["properties"]["token_type_hint"]
        assert "enum" not in hint
    assert (
        "content" not in _operation(app, "/oauth2/revoke", "post")["responses"]["200"]
    )
    token_response = schemas["OAuth2TokenResponse"]["properties"]
    assert token_response["refresh_token"].get("writeOnly") is not True
    assert token_response["id_token"].get("writeOnly") is not True


def test_token_response_description_covers_optional_tokens(app: FastAPI) -> None:
    """Describe token issuance without implying every grant returns a pair."""
    schema = app.openapi()
    response = _operation(app, "/oauth2/token", "post")["responses"]["200"]

    assert response["description"] == (
        "Access token issued, with refresh and ID tokens when applicable."
    )
    assert "token pair" not in str(schema).lower()


def test_sessionless_openapi_omits_browser_oauth2_capabilities(
    sessionless_app: FastAPI,
) -> None:
    """Document only grants and security schemes active without sessions."""
    schema = sessionless_app.openapi()
    OpenAPI.model_validate(schema)

    assert "/api/v1/sessions/login" not in schema["paths"]
    assert "/api/v1/me/sessions" not in schema["paths"]
    assert "/api/v1/me/password" not in schema["paths"]
    assert "delete" not in schema["paths"]["/api/v1/me"]
    assert "/api/v1/server/sessions" not in schema["paths"]
    assert "/oauth2/authorize" not in schema["paths"]
    assert "/oauth2/device_authorization" not in schema["paths"]
    assert "/oauth2/userinfo" not in schema["paths"]
    assert "/.well-known/openid-configuration" not in schema["paths"]
    assert "/oauth2/jwks.json" in schema["paths"]
    token_schema = _form_schema(sessionless_app, "/oauth2/token")
    grant_forms = {item["$ref"].rsplit("/", 1)[1] for item in token_schema["oneOf"]}
    assert grant_forms == {"OAuth2ClientCredentialsGrantForm"}
    schemes = schema["components"]["securitySchemes"]
    assert "APIKeyCookie" not in schemes
    assert "SessionCSRFHeader" not in schemes
    assert "SessionCSRFCookie" not in schemes
    assert "OAuth2AuthorizationCodeBearer" not in schemes
    for path, path_item in schema["paths"].items():
        if not path.startswith("/api/v1/organization/oauth2"):
            continue
        for operation in path_item.values():
            if isinstance(operation, dict):
                assert operation["security"] == [{"HTTPBearer": []}]


def test_application_api_security_matches_enabled_auth_transports(
    app: FastAPI,
) -> None:
    """Advertise only transports that protected application APIs accept."""
    full_schema = app.openapi()
    expected: list[dict[str, list[str]]] = [
        {"APIKeyCookie": []},
        {"HTTPBearer": []},
        {"OAuth2AuthorizationCodeBearer": ["profile:read"]},
    ]
    assert _operation(app, "/api/v1/me", "get")["security"] == expected
    assert full_schema["components"]["securitySchemes"]["APIKeyCookie"]["name"] == (
        app.state.settings.browser_session.cookie_name
    )

    browser_only_app = create_app(Settings(oauth2=OAuth2Settings.disabled()))
    browser_schema = browser_only_app.openapi()

    assert _operation(browser_only_app, "/api/v1/me", "get")["security"] == [
        {"APIKeyCookie": []}
    ]
    assert set(browser_schema["components"]["securitySchemes"]) == {
        "APIKeyCookie",
        "SessionCSRFHeader",
    }
    assert not any(
        path.startswith("/api/v1/organization/oauth2")
        for path in browser_schema["paths"]
    )


def test_organization_user_list_openapi_documents_filters(app: FastAPI) -> None:
    """Publish the closed sort contract and explain every list filter."""
    operation = _operation(app, "/api/v1/organization/users", "get")
    parameters = {parameter["name"]: parameter for parameter in operation["parameters"]}

    sort_schema = parameters["sort"]["schema"]
    sort_values = next(item["enum"] for item in sort_schema["anyOf"] if "enum" in item)
    assert set(sort_values) == {
        "email",
        "-email",
        "first_name",
        "-first_name",
        "last_name",
        "-last_name",
        "active",
        "-active",
        "email_verified",
        "-email_verified",
        "created_at",
        "-created_at",
    }
    for name in (
        "q",
        "sort",
        "role",
        "active",
        "email_verified",
        "created_from",
        "created_to",
        "offset",
        "limit",
    ):
        assert parameters[name]["description"]


@pytest.mark.parametrize(
    ("path", "expected_names", "expected_defaults"),
    [
        (
            "/api/v1/organization/users",
            {
                "q",
                "sort",
                "role",
                "active",
                "email_verified",
                "created_from",
                "created_to",
                "offset",
                "limit",
            },
            {"offset": 0, "limit": 20},
        ),
        (
            "/api/v1/server/users",
            {
                "q",
                "sort",
                "role",
                "operator",
                "active",
                "email_verified",
                "organization_id",
                "created_from",
                "created_to",
                "offset",
                "limit",
            },
            {"offset": 0, "limit": 20},
        ),
        (
            "/api/v1/organization/oauth2/sessions",
            {"client_id", "grant_type", "user_id", "active_only", "offset", "limit"},
            {"active_only": True, "offset": 0, "limit": 100},
        ),
        (
            "/api/v1/me/oauth2/sessions",
            {"offset", "limit"},
            {"offset": 0, "limit": 100},
        ),
        (
            "/api/v1/me/sessions",
            {"active_only", "offset", "limit"},
            {"active_only": True, "offset": 0, "limit": 50},
        ),
        (
            "/api/v1/server/oauth2/clients",
            {"offset", "limit"},
            {"offset": 0, "limit": 20},
        ),
        (
            "/api/v1/server/organizations",
            {"offset", "limit"},
            {"offset": 0, "limit": 20},
        ),
    ],
)
def test_api_list_query_models_preserve_flattened_openapi_parameters(
    app: FastAPI,
    path: str,
    expected_names: set[str],
    expected_defaults: dict[str, object],
) -> None:
    """Keep query models flattened into the existing public parameters."""
    parameters = {
        parameter["name"]: parameter
        for parameter in _operation(app, path, "get")["parameters"]
        if parameter["in"] == "query"
    }

    assert set(parameters) == expected_names
    for name, expected_default in expected_defaults.items():
        assert parameters[name]["schema"]["default"] == expected_default


def test_browser_session_list_openapi_documents_paginated_response(
    app: FastAPI,
) -> None:
    """Expose the browser-session page envelope in the generated contract."""
    response = _operation(app, "/api/v1/me/sessions", "get")["responses"]["200"]
    response_schema = response["content"]["application/json"]["schema"]
    schema_name = response_schema["$ref"].rsplit("/", 1)[1]
    page_schema = app.openapi()["components"]["schemas"][schema_name]

    assert {"items", "offset", "limit", "total"} <= set(page_schema["required"])
    assert page_schema["properties"]["items"]["items"] == {
        "$ref": "#/components/schemas/CurrentUserBrowserSessionResponse"
    }


def test_openapi_groups_current_organization_routes_under_singular_prefix(
    app: FastAPI,
) -> None:
    """Publish one explicit current-organization resource hierarchy."""
    paths = app.openapi()["paths"]

    assert {
        "/api/v1/organization",
        "/api/v1/organization/users",
        "/api/v1/organization/users/{user_id}",
        "/api/v1/organization/oauth2/sessions",
        "/api/v1/organization/oauth2/sessions/{session_id}",
        "/api/v1/organization/oauth2/clients/{client_id}/tokens",
    } <= set(paths)
    assert not {
        "/api/v1/organizations",
        "/api/v1/users",
        "/api/v1/users/{user_id}",
        "/api/v1/oauth2/sessions",
        "/api/v1/oauth2/sessions/{session_id}",
        "/api/v1/oauth2/clients/{client_id}/tokens",
    } & set(paths)


# Keep the route matrix and security-scope assertions together as one contract test.
def test_application_api_security_uses_fastapi_permission_scopes(  # noqa: C901
    app: FastAPI,
) -> None:
    """Publish route permissions as OAuth2 scopes while retaining other transports."""

    def expected(scope: str, *, csrf: bool = False) -> list[dict[str, list[str]]]:
        session_security: dict[str, list[str]] = {"APIKeyCookie": []}
        if csrf:
            session_security["SessionCSRFHeader"] = []
        return [
            session_security,
            {"HTTPBearer": []},
            {"OAuth2AuthorizationCodeBearer": [scope]},
        ]

    assert _operation(app, "/api/v1/organization", "get")["security"] == expected(
        "organization:read"
    )
    assert _operation(app, "/api/v1/organization", "patch")["security"] == expected(
        "organization:write", csrf=True
    )
    assert _operation(app, "/api/v1/server/organizations", "get")[
        "security"
    ] == expected("organizations:read")
    assert _operation(app, "/api/v1/server/organizations", "post")[
        "security"
    ] == expected("organizations:write", csrf=True)
    assert _operation(app, "/api/v1/server/users", "get")["security"] == expected(
        "users:read"
    )
    assert _operation(app, "/api/v1/server/oauth2/clients", "post")[
        "security"
    ] == expected("oauth2_clients:write", csrf=True)
    assert _operation(
        app, "/api/v1/organization/oauth2/sessions/{session_id}", "delete"
    )["security"] == expected("organization:write", csrf=True)

    for path, path_item in app.openapi()["paths"].items():
        if not path.startswith("/api/v1/organization"):
            continue
        for method, operation in path_item.items():
            if method not in {"get", "post", "put", "patch", "delete"}:
                continue
            expected_scope = (
                "organization:read" if method == "get" else "organization:write"
            )
            oauth2_requirement = next(
                requirement
                for requirement in operation["security"]
                if "OAuth2AuthorizationCodeBearer" in requirement
            )
            assert oauth2_requirement == {
                "OAuth2AuthorizationCodeBearer": [expected_scope]
            }

    for path, path_item in app.openapi()["paths"].items():
        if not path.startswith("/api/v1/server"):
            continue
        for method, operation in path_item.items():
            if method not in {"get", "post", "put", "patch", "delete"}:
                continue
            action = "read" if method == "get" else "write"
            if path.startswith("/api/v1/server/oauth2"):
                expected_scope = f"oauth2_clients:{action}"
            elif path == "/api/v1/server/sessions" or path.endswith("/sessions"):
                expected_scope = "sessions:write"
            elif path.startswith("/api/v1/server/organizations"):
                expected_scope = f"organizations:{action}"
            else:
                expected_scope = f"users:{action}"
            oauth2_requirement = next(
                requirement
                for requirement in operation["security"]
                if "OAuth2AuthorizationCodeBearer" in requirement
            )
            assert oauth2_requirement == {
                "OAuth2AuthorizationCodeBearer": [expected_scope]
            }


def test_mixed_authentication_writes_describe_csrf_as_session_only(
    app: FastAPI,
) -> None:
    """Do not imply that Bearer-authenticated writes require CSRF proof."""
    operations = (
        ("/api/v1/me", "patch"),
        ("/api/v1/server/organizations", "post"),
        ("/api/v1/server/users", "post"),
        ("/api/v1/server/oauth2/clients", "post"),
        ("/api/v1/server/sessions", "delete"),
        ("/api/v1/organization/oauth2/sessions/{session_id}", "delete"),
    )

    for path, method in operations:
        description = _operation(app, path, method)["responses"]["403"]["description"]
        assert "browser-session request" in description


def test_global_session_deletion_openapi_names_the_deletion_scope(
    app: FastAPI,
) -> None:
    """Describe inactive-versus-all selection as a deletion scope."""
    operation = _operation(app, "/api/v1/server/sessions", "delete")

    query_parameter = next(
        parameter for parameter in operation["parameters"] if parameter["in"] == "query"
    )

    assert query_parameter["name"] == "scope"
    assert query_parameter["schema"]["enum"] == ["inactive", "all"]


def test_organization_oauth2_operations_document_runtime_errors(app: FastAPI) -> None:
    """Publish authentication, authorization, validation, and lookup errors."""
    list_operation = _operation(app, "/api/v1/organization/oauth2/sessions", "get")
    client_revoke = _operation(
        app, "/api/v1/organization/oauth2/clients/{client_id}/tokens", "delete"
    )
    session_revoke = _operation(
        app, "/api/v1/organization/oauth2/sessions/{session_id}", "delete"
    )

    assert set(list_operation["responses"]) == {"200", "401", "403", "422", "503"}
    assert set(client_revoke["responses"]) == {"200", "401", "403", "422", "503"}
    assert set(session_revoke["responses"]) == {
        "200",
        "401",
        "403",
        "404",
        "422",
        "503",
    }
    for operation in (list_operation, client_revoke, session_revoke):
        for status_code in ("401", "403"):
            schema = operation["responses"][status_code]["content"]["application/json"][
                "schema"
            ]
            assert schema == {"$ref": "#/components/schemas/ErrorResponse"}
    assert "session" in session_revoke["responses"]["404"]["description"].lower()


def test_organization_request_schemas_match_runtime_validation(app: FastAPI) -> None:
    """Publish invitation password rules and optional non-null patch fields."""
    schemas = app.openapi()["components"]["schemas"]
    for schema_name in (
        "RegistrationResponse",
        "OrganizationUserResponse",
        "ServerUserResponse",
        "CurrentUserProfileResponse",
    ):
        assert "email_verified" in schemas[schema_name]["properties"]

    organization_user_required = set(schemas["OrganizationUserResponse"]["required"])
    assert {"pending_email", "email_verified"} <= organization_user_required
    server_user_required = set(schemas["ServerUserResponse"]["required"])
    assert {
        "organization_id",
        "pending_email",
        "is_operator",
        "email_verified",
    } <= server_user_required

    paginated_schemas = [
        schema
        for name, schema in schemas.items()
        if name.startswith("PaginatedResponse_")
    ]
    assert paginated_schemas
    assert all(
        {"items", "offset", "limit", "total"} <= set(schema["required"])
        for schema in paginated_schemas
    )
    registration = schemas["RegistrationResponse"]["properties"]
    assert registration["id"]["format"] == "uuid4"
    assert registration["organization_id"]["format"] == "uuid4"
    create_password = schemas["OrganizationUserCreateRequest"]["properties"]["password"]
    password_schema = next(
        item for item in create_password["anyOf"] if item.get("type") == "string"
    )

    assert password_schema["minLength"] == MIN_PASSWORD_LENGTH
    assert password_schema["maxLength"] == MAX_PASSWORD_LENGTH
    assert create_password["writeOnly"] is True
    assert "invite" in create_password["description"].lower()

    patch_properties = schemas["OrganizationUserPatchRequest"]["properties"]
    assert set(patch_properties) == {
        "email",
        "first_name",
        "last_name",
        "is_active",
        "role",
    }
    assert all("anyOf" not in schema for schema in patch_properties.values())
    assert all(schema.get("type") != "null" for schema in patch_properties.values())
    assert (
        "email_verified" not in schemas["OrganizationUserCreateRequest"]["properties"]
    )
    assert (
        "email_verified" not in schemas["OrganizationUserReplaceRequest"]["properties"]
    )
    for organization_schema in (
        "OrganizationUserCreateRequest",
        "OrganizationUserPatchRequest",
        "OrganizationUserReplaceRequest",
        "OrganizationUserResponse",
    ):
        assert "is_operator" not in schemas[organization_schema]["properties"]
    server_create = schemas["ServerUserCreateRequest"]["properties"]
    assert {"password", "is_active", "email_verified"}.isdisjoint(server_create)
    assert {
        "organization_id",
        "email",
        "first_name",
        "last_name",
        "role",
        "is_operator",
    } == set(server_create)
    for server_schema in ("ServerUserPatchRequest", "ServerUserReplaceRequest"):
        assert "email_verified" in schemas[server_schema]["properties"]
    server_patch = schemas["ServerUserPatchRequest"]["properties"]
    for property_name in ("organization_id", "is_operator", "email_verified"):
        assert "anyOf" not in server_patch[property_name]
        assert server_patch[property_name].get("type") != "null"


def test_admin_operations_publish_precise_response_contracts(app: FastAPI) -> None:
    """Document only the responses each server-administration route can return."""
    expected = {
        ("/api/v1/server/organizations", "get"): {"200", "401", "403", "422"},
        ("/api/v1/server/organizations", "post"): {
            "201",
            "401",
            "403",
            "409",
            "422",
        },
        ("/api/v1/server/organizations/{organization_id}", "get"): {
            "200",
            "401",
            "403",
            "404",
            "422",
        },
        ("/api/v1/server/organizations/{organization_id}", "patch"): {
            "200",
            "401",
            "403",
            "404",
            "409",
            "422",
        },
        ("/api/v1/server/users", "get"): {"200", "400", "401", "403", "422"},
        ("/api/v1/server/users", "post"): {"201", "401", "403", "404", "409", "422"},
        ("/api/v1/server/users/{user_id}", "get"): {"200", "401", "403", "404", "422"},
        ("/api/v1/server/users/{user_id}", "patch"): {
            "200",
            "401",
            "403",
            "404",
            "409",
            "422",
        },
        ("/api/v1/server/users/{user_id}", "put"): {
            "200",
            "401",
            "403",
            "404",
            "409",
            "422",
        },
        ("/api/v1/server/users/{user_id}", "delete"): {
            "204",
            "401",
            "403",
            "404",
            "409",
            "422",
        },
        ("/api/v1/server/oauth2/clients", "get"): {"200", "401", "403", "422"},
        ("/api/v1/server/oauth2/clients", "post"): {
            "201",
            "400",
            "401",
            "403",
            "409",
            "422",
        },
        ("/api/v1/server/oauth2/clients/{client_id}", "get"): {
            "200",
            "401",
            "403",
            "404",
            "422",
        },
        ("/api/v1/server/oauth2/clients/{client_id}", "put"): {
            "200",
            "400",
            "401",
            "403",
            "404",
            "409",
            "422",
        },
        ("/api/v1/server/oauth2/clients/{client_id}", "delete"): {
            "204",
            "401",
            "403",
            "404",
            "422",
        },
        ("/api/v1/server/oauth2/clients/{client_id}/user-organizations", "get"): {
            "200",
            "401",
            "403",
            "404",
            "422",
        },
        ("/api/v1/server/oauth2/clients/{client_id}/user-organizations", "put"): {
            "200",
            "400",
            "401",
            "403",
            "404",
            "409",
            "422",
        },
        ("/api/v1/server/oauth2/clients/{client_id}/machine-organizations", "get"): {
            "200",
            "401",
            "403",
            "404",
            "422",
        },
        ("/api/v1/server/oauth2/clients/{client_id}/machine-organizations", "put"): {
            "200",
            "400",
            "401",
            "403",
            "404",
            "409",
            "422",
        },
        ("/api/v1/server/oauth2/clients/{client_id}/secrets", "post"): {
            "200",
            "400",
            "401",
            "403",
            "404",
            "422",
        },
        ("/api/v1/server/sessions", "delete"): {"200", "401", "403", "422"},
        ("/api/v1/server/organizations/{organization_id}/sessions", "delete"): {
            "204",
            "401",
            "403",
            "404",
            "422",
        },
    }

    for (path, method), status_codes in expected.items():
        operation = _operation(app, path, method)
        assert set(operation["responses"]) == status_codes | {"503"}
        for status_code in status_codes - {"200", "201", "204", "422"}:
            response_schema = operation["responses"][status_code]["content"][
                "application/json"
            ]["schema"]
            assert response_schema == {"$ref": "#/components/schemas/ErrorResponse"}


def test_admin_parameters_and_secret_responses_are_documented(app: FastAPI) -> None:
    """Publish typed filters, client identifiers, and one-time secret handling."""
    schema = app.openapi()
    user_parameters = {
        parameter["name"]: parameter
        for parameter in _operation(app, "/api/v1/server/users", "get")["parameters"]
    }
    sort_values = next(
        item["enum"]
        for item in user_parameters["sort"]["schema"]["anyOf"]
        if "enum" in item
    )
    assert set(sort_values) == {
        "email",
        "-email",
        "first_name",
        "-first_name",
        "last_name",
        "-last_name",
        "active",
        "-active",
        "email_verified",
        "-email_verified",
        "operator",
        "-operator",
        "created_at",
        "-created_at",
    }
    for name in (
        "active",
        "email_verified",
        "organization_id",
        "created_from",
        "created_to",
        "offset",
        "limit",
    ):
        assert user_parameters[name]["description"]

    client_parameter = next(
        parameter
        for parameter in _operation(
            app, "/api/v1/server/oauth2/clients/{client_id}", "get"
        )["parameters"]
        if parameter["name"] == "client_id"
    )
    assert client_parameter["schema"]["format"] == "uuid4"
    assert client_parameter["description"]

    for path, method, status_code in (
        ("/api/v1/server/oauth2/clients", "post", "201"),
        ("/api/v1/server/oauth2/clients/{client_id}/secrets", "post", "200"),
    ):
        response = _operation(app, path, method)["responses"][status_code]
        assert response["headers"]["Cache-Control"]["schema"]["const"] == "no-store"
        assert response["headers"]["Pragma"]["schema"]["const"] == "no-cache"
    secret = schema["components"]["schemas"]["OAuth2ClientSecretResponse"][
        "properties"
    ]["client_secret"]
    assert "once" in secret["description"].lower()


def test_organization_operations_publish_precise_response_contracts(
    app: FastAPI,
) -> None:
    """Document only errors that each current-organization operation can return."""
    expected = {
        ("/api/v1/organization", "get"): {"200", "401", "403", "404"},
        ("/api/v1/organization", "patch"): {"200", "401", "403", "404", "409", "422"},
        ("/api/v1/organization/users", "get"): {
            "200",
            "400",
            "401",
            "403",
            "422",
        },
        ("/api/v1/organization/users", "post"): {"201", "401", "403", "409", "422"},
        ("/api/v1/organization/users/{user_id}", "get"): {
            "200",
            "401",
            "403",
            "404",
            "422",
        },
        ("/api/v1/organization/users/{user_id}", "patch"): {
            "200",
            "401",
            "403",
            "404",
            "409",
            "422",
        },
        ("/api/v1/organization/users/{user_id}", "put"): {
            "200",
            "401",
            "403",
            "404",
            "409",
            "422",
        },
        ("/api/v1/organization/users/{user_id}", "delete"): {
            "204",
            "401",
            "403",
            "404",
            "409",
            "422",
        },
    }

    for (path, method), status_codes in expected.items():
        operation = _operation(app, path, method)
        assert set(operation["responses"]) == status_codes | {"503"}
        for status_code in status_codes - {"200", "201", "204", "422"}:
            schema = operation["responses"][status_code]["content"]["application/json"][
                "schema"
            ]
            assert schema == {"$ref": "#/components/schemas/ErrorResponse"}


def test_organization_oauth2_session_list_documents_filters_and_cache_header(
    app: FastAPI,
) -> None:
    """Describe every session filter and its sensitive response cache policy."""
    operation = _operation(app, "/api/v1/organization/oauth2/sessions", "get")
    parameters = {parameter["name"]: parameter for parameter in operation["parameters"]}

    for name in (
        "client_id",
        "grant_type",
        "user_id",
        "active_only",
        "offset",
        "limit",
    ):
        assert parameters[name]["description"]
    cache_control = operation["responses"]["200"]["headers"]["Cache-Control"]
    assert cache_control["schema"]["const"] == "no-store"
    grant_schema = parameters["grant_type"]["schema"]["anyOf"][0]
    grant_reference = grant_schema["$ref"].rsplit("/", 1)[1]
    assert app.openapi()["components"]["schemas"][grant_reference]["enum"] == [
        "authorization_code",
        "client_credentials",
        "urn:ietf:params:oauth:grant-type:device_code",
    ]


def test_current_user_oauth2_session_list_documents_pagination(app: FastAPI) -> None:
    """Keep the self-service session pagination contract visible in OpenAPI."""
    operation = _operation(app, "/api/v1/me/oauth2/sessions", "get")
    parameters = {parameter["name"]: parameter for parameter in operation["parameters"]}

    assert parameters["offset"]["schema"]["minimum"] == 0
    assert parameters["limit"]["schema"]["minimum"] == 1
    assert parameters["limit"]["schema"]["maximum"] == DEFAULT_PAGE_LIMIT_MAX


def test_current_user_oauth2_sessions_use_canonical_session_identifiers(
    app: FastAPI,
) -> None:
    """Expose one canonical OAuth2 session identifier across administration views."""
    schema = app.openapi()
    session_id = {
        parameter["name"]: parameter
        for parameter in _operation(
            app,
            "/api/v1/me/oauth2/sessions/{session_id}",
            "delete",
        )["parameters"]
    }["session_id"]
    response_id = schema["components"]["schemas"]["CurrentUserOAuth2SessionResponse"][
        "properties"
    ]["id"]
    organization_properties = schema["components"]["schemas"][
        "OrganizationOAuth2SessionResponse"
    ]["properties"]

    assert session_id["schema"]["format"] == "uuid4"
    assert response_id["format"] == "uuid4"
    assert organization_properties["id"]["format"] == "uuid4"
    assert organization_properties["scopes"]["items"] == {"type": "string"}
    assert "session_id" not in organization_properties
    assert "scope" not in organization_properties
    assert "oau_" not in repr(schema)


def test_current_user_operations_document_authentication_and_csrf_errors(
    app: FastAPI,
) -> None:
    """Publish the authentication and CSRF failures returned by `/me` routes."""
    read_operations = (
        _operation(app, "/api/v1/me", "get"),
        _operation(app, "/api/v1/me/sessions", "get"),
        _operation(app, "/api/v1/me/oauth2/sessions", "get"),
    )
    write_operations = (
        _operation(app, "/api/v1/me", "patch"),
        _operation(app, "/api/v1/me", "delete"),
        _operation(app, "/api/v1/me/password", "post"),
        _operation(app, "/api/v1/me/sessions/{session_id}", "delete"),
        _operation(
            app,
            "/api/v1/me/oauth2/sessions/{session_id}",
            "delete",
        ),
    )

    for operation in (*read_operations, *write_operations):
        assert "401" in operation["responses"]
        response_schema = operation["responses"]["401"]["content"]["application/json"][
            "schema"
        ]
        assert response_schema == {"$ref": "#/components/schemas/ErrorResponse"}
    for operation in write_operations:
        assert "403" in operation["responses"]
        csrf_examples = operation["responses"]["403"]["content"]["application/json"][
            "examples"
        ]
        assert "CSRF_MISSING_HEADER" in csrf_examples
        assert "CSRF_REQUEST_SOURCE_MISSING" in csrf_examples
        assert "CSRF_REQUEST_SOURCE_UNTRUSTED" in csrf_examples


def test_organization_session_revocation_openapi_contract(app: FastAPI) -> None:
    """Document explicit-organization machine and operator session revocation."""
    operation = _operation(
        app,
        "/api/v1/server/organizations/{organization_id}/sessions",
        "delete",
    )
    assert operation["security"] == [
        {"APIKeyCookie": [], "SessionCSRFHeader": []},
        {"HTTPBearer": []},
        {"OAuth2AuthorizationCodeBearer": ["sessions:write"]},
    ]
    assert set(operation["responses"]) >= {"204", "401", "403", "404"}
    assert "content" not in operation["responses"]["204"]
    assert "client-credentials" in operation["description"]
    organization_parameter = next(
        parameter
        for parameter in operation["parameters"]
        if parameter["name"] == "organization_id"
    )
    assert organization_parameter["in"] == "path"
    assert organization_parameter["required"] is True


def test_profile_and_password_change_openapi_contracts_are_separate(
    app: FastAPI,
) -> None:
    """Keep credentials out of profile schemas and mark password inputs write-only."""
    schema = app.openapi()
    components = schema["components"]["schemas"]

    assert "put" not in schema["paths"]["/api/v1/me"]
    for method in ("get", "patch"):
        response_schema = _operation(app, "/api/v1/me", method)["responses"]["200"][
            "content"
        ]["application/json"]["schema"]
        assert response_schema == {
            "$ref": "#/components/schemas/CurrentUserProfileResponse"
        }
    self_profile = components["CurrentUserProfileResponse"]
    assert {"id", "user_id", "organization_id", "is_operator"}.isdisjoint(
        self_profile["properties"]
    )
    assert self_profile["properties"]["organization"] == {
        "$ref": "#/components/schemas/CurrentUserOrganizationResponse",
        "description": "Organization associated with the current identity.",
    }
    assert set(components["CurrentUserOrganizationResponse"]["properties"]) == {"name"}
    request_schema = _operation(app, "/api/v1/me", "patch")["requestBody"]["content"][
        "application/json"
    ]["schema"]
    assert request_schema == {
        "$ref": "#/components/schemas/CurrentUserProfilePatchRequest"
    }
    assert "password" not in components["CurrentUserProfilePatchRequest"]["properties"]
    assert "UserSelfUpdate" not in components

    password_operation = _operation(app, "/api/v1/me/password", "post")
    session_write_security: list[dict[str, list[str]]] = [
        {"APIKeyCookie": [], "SessionCSRFHeader": []}
    ]
    assert password_operation["security"] == session_write_security
    assert _operation(app, "/api/v1/me", "delete")["security"] == session_write_security
    password_schema = password_operation["requestBody"]["content"]["application/json"][
        "schema"
    ]
    password_model = components[password_schema["$ref"].rsplit("/", 1)[1]]
    assert set(password_model["required"]) == {"current_password", "new_password"}
    assert all(
        password_model["properties"][field]["writeOnly"]
        for field in ("current_password", "new_password")
    )
    assert password_operation["responses"]["204"]["description"] == (
        "Password changed and security sessions revoked."
    )


def test_identity_workflow_openapi_documents_domain_errors(app: FastAPI) -> None:
    """Expose workflow and self-service failures in the public API contract."""
    registration = _operation(app, "/api/v1/auth/register", "post")
    assert (
        "ALREADY_EXISTS"
        in registration["responses"]["409"]["content"]["application/json"]["examples"]
    )

    confirmation_paths = (
        "/api/v1/auth/email/change/confirm",
        "/api/v1/auth/email/verify/confirm",
        "/api/v1/auth/invite/accept",
        "/api/v1/auth/password/reset",
    )
    for path in confirmation_paths:
        response = _operation(app, path, "post")["responses"]["400"]
        assert (
            "INVALID_WORKFLOW_TOKEN"
            in response["content"]["application/json"]["examples"]
        )

    schemas = app.openapi()["components"]["schemas"]
    assert schemas["RegisterRequest"]["properties"]["password"]["writeOnly"] is True
    assert (
        schemas["WorkflowTokenConfirmRequest"]["properties"]["token"]["writeOnly"]
        is True
    )
    password_workflow = schemas["PasswordWorkflowTokenRequest"]["properties"]
    assert password_workflow["token"]["writeOnly"] is True
    assert password_workflow["password"]["writeOnly"] is True

    profile_conflict = _operation(app, "/api/v1/me", "patch")["responses"]["409"]
    assert (
        "ALREADY_EXISTS" in profile_conflict["content"]["application/json"]["examples"]
    )

    deletion = _operation(app, "/api/v1/me", "delete")["responses"]
    forbidden_examples = deletion["403"]["content"]["application/json"]["examples"]
    assert {
        "FORBIDDEN_OPERATION",
        "CSRF_MISSING_COOKIE",
        "CSRF_MISSING_HEADER",
        "CSRF_COOKIE_HEADER_MISMATCH",
        "CSRF_REQUEST_SOURCE_MISSING",
        "CSRF_REQUEST_SOURCE_UNTRUSTED",
        "CSRF_HEADER_SESSION_MISMATCH",
    } <= set(forbidden_examples)
    assert {
        "LAST_ACTIVE_OPERATOR",
        "LAST_ACTIVE_ORGANIZATION_ADMIN",
    } <= set(deletion["409"]["content"]["application/json"]["examples"])

    for method in ("patch", "put", "delete"):
        operator_user_conflict = _operation(
            app, "/api/v1/server/users/{user_id}", method
        )["responses"]["409"]
        assert {
            "LAST_ACTIVE_OPERATOR",
            "LAST_ACTIVE_ORGANIZATION_ADMIN",
        } <= set(operator_user_conflict["content"]["application/json"]["examples"])

    for path in (
        "/api/v1/server/users",
        "/api/v1/server/users/{user_id}/invitation",
        "/api/v1/organization/users",
        "/api/v1/organization/users/{user_id}/invitation",
    ):
        method = "post"
        conflict_examples = _operation(app, path, method)["responses"]["409"][
            "content"
        ]["application/json"]["examples"]
        assert "LAST_ACTIVE_OPERATOR" not in conflict_examples
        assert "LAST_ACTIVE_ORGANIZATION_ADMIN" not in conflict_examples

    invitation_paths = (
        "/api/v1/server/users/{user_id}/invitation",
        "/api/v1/organization/users/{user_id}/invitation",
    )
    for path in invitation_paths:
        invitation_examples = _operation(app, path, "post")["responses"]["409"][
            "content"
        ]["application/json"]["examples"]
        assert set(invitation_examples) == {"INACTIVE_USER_INVITATION"}

    for path in ("/api/v1/server/users", "/api/v1/organization/users"):
        date_range_examples = _operation(app, path, "get")["responses"]["400"][
            "content"
        ]["application/json"]["examples"]
        assert "START_DATE_AFTER_END_DATE" in date_range_examples

    organization_deletion = _operation(
        app, "/api/v1/organization/users/{user_id}", "delete"
    )["responses"]["409"]
    assert (
        "LAST_ACTIVE_ORGANIZATION_ADMIN"
        in organization_deletion["content"]["application/json"]["examples"]
    )


def test_openapi_represents_oauth2_with_no_enabled_grants() -> None:
    """Avoid advertising token request variants when every grant is disabled."""
    oauth2 = OAuth2Settings().model_copy(
        update={
            "authorization_code_enabled": False,
            "refresh_token_enabled": False,
            "client_credentials_enabled": False,
            "device_code_enabled": False,
            "oidc_enabled": False,
        }
    )
    no_grants_app = create_app(
        Settings(
            browser_session=BrowserSessionSettings(enabled=True),
            ui=UISettings(
                oauth2_interaction=OAuth2InteractionUIMode.DISABLED,
            ),
            oauth2=oauth2,
        )
    )

    schema = no_grants_app.openapi()
    OpenAPI.model_validate(schema)
    assert "/oauth2/token" not in schema["paths"]
    assert "/oauth2/jwks.json" in schema["paths"]
    assert "/api/v1/me/oauth2/sessions" not in schema["paths"]
    assert "/api/v1/server/oauth2/clients" not in schema["paths"]
    assert not any(
        path.startswith("/api/v1/organization/oauth2") for path in schema["paths"]
    )


def test_device_forms_and_referenced_security_schemes_are_defined(
    app: FastAPI,
) -> None:
    """Expose device forms and define every security scheme they reference."""
    assert set(_form_schema(app, "/oauth2/device_authorization")["properties"]) == {
        "client_id",
        "client_secret",
        "scope",
    }
    assert _operation(app, "/oauth2/device_authorization", "post")["requestBody"][
        "required"
    ]
    assert "/oauth2/device/verify" in app.openapi()["paths"]

    schema = app.openapi()
    OpenAPI.model_validate(schema)
    schemes = schema["components"]["securitySchemes"]
    assert schemes["APIKeyCookie"]["in"] == "cookie"
    assert schemes["OAuth2ClientBasic"]["scheme"] == "basic"
    assert schemes["HTTPBearer"]["scheme"] == "bearer"
    assert "authorizationCode" in schemes["OAuth2AuthorizationCodeBearer"]["flows"]
    scopes = schemes["OAuth2AuthorizationCodeBearer"]["flows"]["authorizationCode"][
        "scopes"
    ]
    assert scopes["organization:read"] == (
        "Read resources in the current organization administration API."
    )
    assert scopes["organization:write"] == (
        "Change resources in the current organization administration API."
    )
    assert "server API" in scopes["organizations:read"]
    assert "server API" in scopes["users:write"]
    assert "server API" in scopes["sessions:write"]
    assert "server API" in scopes["oauth2_clients:read"]
    assert all("password" not in scheme.get("flows", {}) for scheme in schemes.values())
    for path_item in schema["paths"].values():
        for operation in path_item.values():
            if not isinstance(operation, dict):
                continue
            for requirement in operation.get("security", []):
                assert set(requirement) <= set(schemes)


def test_userinfo_and_discovery_openapi_contract(app: FastAPI) -> None:
    """Require Bearer UserInfo and non-null issuer metadata URLs."""
    for method in ("get", "post"):
        operation = _operation(app, "/oauth2/userinfo", method)
        assert operation["security"] == [{"HTTPBearer": []}]
        assert "422" not in operation["responses"]
        for error_status in ("401", "403"):
            error_response = operation["responses"][error_status]
            assert error_response["content"]["application/json"]["schema"] == {
                "$ref": "#/components/schemas/OAuth2ErrorResponse"
            }
            assert error_response["headers"]["WWW-Authenticate"]["schema"] == {
                "type": "string"
            }
    schemas = app.openapi()["components"]["schemas"]
    userinfo = schemas["UserInfoResponse"]
    assert userinfo["required"] == ["sub"]
    assert userinfo["properties"]["sub"]["format"] == "uuid4"
    assert userinfo["properties"]["sub"]["type"] == "string"
    assert userinfo["properties"]["email"]["format"] == "email"
    assert userinfo["properties"]["email"]["type"] == "string"
    assert userinfo["properties"]["email_verified"]["type"] == "boolean"
    assert userinfo["properties"]["name"]["type"] == "string"
    assert userinfo["properties"]["given_name"]["type"] == "string"
    assert userinfo["properties"]["family_name"]["type"] == "string"
    for field in ("email", "email_verified", "name", "given_name", "family_name"):
        assert "anyOf" not in userinfo["properties"][field]
    oidc_metadata = schemas["OpenIDProviderMetadata"]
    assert "jwks_uri" in oidc_metadata["required"]
    assert "token_endpoint_auth_methods_supported" in oidc_metadata["required"]
    for field in (
        "issuer",
        "authorization_endpoint",
        "token_endpoint",
        "userinfo_endpoint",
        "jwks_uri",
    ):
        assert oidc_metadata["properties"][field]["format"] == "uri"


def test_oauth2_admin_openapi_uses_public_identifiers(app: FastAPI) -> None:
    """Keep OAuth2 client administration on public schema fields."""
    schema = app.openapi()
    schemas = schema["components"]["schemas"]
    client = schemas["OAuth2ClientReadResponse"]["properties"]
    create = schemas["OAuth2ClientCreateRequest"]["properties"]
    replacement = schemas["OAuth2ClientReplaceRequest"]["properties"]

    assert "organization_id" not in client
    assert "machine_organization_access" not in create
    assert "machine_organization_access" not in replacement
    assert "user_organization_access" not in replacement
    assert "user_organization_ids" not in replacement
    assert create["name"]["minLength"] == 1
    assert replacement["name"]["minLength"] == 1
    assert (
        create["user_organization_ids"]["maxItems"]
        == OAuth2Specs.CLIENT_ORGANIZATION_ASSIGNMENTS_MAX
    )
    user_policy_request = schemas["OAuth2ClientUserOrganizationsRequest"]
    assert set(user_policy_request["required"]) == {
        "user_organization_access",
        "organization_ids",
    }
    assert client["is_active"]["type"] == "boolean"
    access = client["user_organization_access"]
    enum_schema_name = access["$ref"].rsplit("/", 1)[-1]
    assert schemas[enum_schema_name]["enum"] == [
        "unrestricted",
        "single",
        "selected",
    ]
    assert (
        "/api/v1/server/oauth2/clients/{client_id}/user-organizations"
        in schema["paths"]
    )
    machine_access = client["machine_organization_access"]
    machine_enum_name = machine_access["$ref"].rsplit("/", 1)[-1]
    assert schemas[machine_enum_name]["enum"] == [
        "none",
        "single",
        "selected",
        "unrestricted",
    ]
    assert (
        "/api/v1/server/oauth2/clients/{client_id}/machine-organizations"
        in schema["paths"]
    )
    create_errors = schema["paths"]["/api/v1/server/oauth2/clients"]["post"][
        "responses"
    ]["400"]["content"]["application/json"]["examples"]
    invalid_client = create_errors["INVALID_OAUTH2_CLIENT"]["value"]
    assert invalid_client["details"] == [
        {
            "location": [],
            "message": "The requested OAuth2 client configuration is invalid.",
            "type": "oauth2_client_configuration_invalid",
        }
    ]


def test_oauth2_metadata_openapi_does_not_claim_jwt_client_authentication(
    app: FastAPI,
) -> None:
    """Keep unsupported JWT client-authentication algorithms out of the contract."""
    metadata = app.openapi()["components"]["schemas"][
        "OAuth2AuthorizationServerMetadata"
    ]

    assert (
        "token_endpoint_auth_signing_alg_values_supported" not in metadata["properties"]
    )
    assert "scopes_supported" not in metadata["properties"]


def test_browser_session_openapi_uses_no_content_success_responses(
    app: FastAPI,
) -> None:
    """Keep browser-session transport routes bodyless on success."""
    assert "/session/login" not in app.openapi()["paths"]
    assert "/session/logout" not in app.openapi()["paths"]
    assert "/session/csrf" not in app.openapi()["paths"]
    for path in ("/api/v1/sessions/login", "/api/v1/sessions/logout"):
        operation = _operation(app, path, "post")
        assert operation["responses"]["204"]["description"]
        assert "content" not in operation["responses"]["204"]

    login_operation = _operation(app, "/api/v1/sessions/login", "post")
    assert login_operation["responses"]["403"]["description"]
    assert "422" in login_operation["responses"]
    assert "application/json" in login_operation["requestBody"]["content"]
    parameters = {
        (parameter["in"], parameter["name"]): parameter
        for parameter in login_operation["parameters"]
    }
    assert parameters[("header", "Origin")]["required"] is False
    assert parameters[("header", "Referer")]["required"] is False
    assert parameters[("header", app.state.settings.browser_session.csrf.header_name)][
        "required"
    ]
    assert parameters[("cookie", app.state.settings.browser_session.csrf.cookie_name)][
        "required"
    ]
    assert "security" not in login_operation

    logout_operation = _operation(app, "/api/v1/sessions/logout", "post")
    assert "application/json" in logout_operation["requestBody"]["content"]
    assert logout_operation["requestBody"]["required"] is False
    assert "/api/v1/sessions/logout-all" not in app.openapi()["paths"]
    assert _operation(app, "/api/v1/me/sessions", "get")["security"] == [
        {"APIKeyCookie": []}
    ]
    revoke_session_operation = _operation(
        app, "/api/v1/me/sessions/{session_id}", "delete"
    )
    assert revoke_session_operation["responses"]["409"]["description"] == (
        "Current session must be ended through logout."
    )
    csrf_operation = _operation(app, "/api/v1/sessions/csrf", "get")
    assert csrf_operation["responses"]["204"]["description"]
    assert "security" not in csrf_operation


def test_login_openapi_uses_configured_cookie_and_csrf_names() -> None:
    """Reflect dynamic browser transport names in the finalized schema."""
    custom_app = create_app(
        Settings(
            ui=UISettings(
                identity_workflow_mode=IdentityWorkflowUIMode.EXTERNAL,
                management_authentication=ManagementAuthenticationMode.EXTERNAL,
                urls={
                    "login": EXTERNAL_LOGIN_URL,
                    "logout": "https://frontend.test/logout",
                },
            ),
            browser_session=BrowserSessionSettings(
                cookie_name="zero_session",
                csrf=CSRFSettings(
                    cookie_name="zero_csrf",
                    header_name="X-Zero-CSRF",
                ),
            ),
        )
    )
    schema = custom_app.openapi()
    parameters = {
        (parameter["in"], parameter["name"])
        for parameter in schema["paths"]["/api/v1/sessions/login"]["post"]["parameters"]
    }

    assert schema["components"]["securitySchemes"]["APIKeyCookie"]["name"] == (
        "zero_session"
    )
    assert (
        schema["components"]["securitySchemes"]["SessionCSRFHeader"]["name"]
        == "X-Zero-CSRF"
    )
    assert _operation(custom_app, "/api/v1/organization", "patch")["security"][0] == {
        "APIKeyCookie": [],
        "SessionCSRFHeader": [],
    }
    assert ("header", "X-Zero-CSRF") in parameters
    assert ("cookie", "zero_csrf") in parameters
    login_request = schema["components"]["schemas"]["LoginRequest"]
    assert login_request["properties"]["email"]["maxLength"] == (
        UserSpecs.EMAIL_LENGTH_MAX
    )
    assert login_request["properties"]["password"]["writeOnly"] is True


def test_double_submit_openapi_requires_matching_csrf_cookie() -> None:
    """Document both client-supplied CSRF values in double-submit mode."""
    app = create_app(
        Settings(
            browser_session=BrowserSessionSettings(
                csrf=CSRFSettings(pattern=CSRFPattern.DOUBLE_SUBMIT)
            )
        )
    )
    schema = app.openapi()

    assert schema["components"]["securitySchemes"]["SessionCSRFCookie"]["name"] == (
        app.state.settings.browser_session.csrf.cookie_name
    )
    assert _operation(app, "/api/v1/organization", "patch")["security"][0] == {
        "APIKeyCookie": [],
        "SessionCSRFHeader": [],
        "SessionCSRFCookie": [],
    }
