"""OpenAPI contracts for server-rendered form models."""

from typing import Any, cast

import pytest
from app.main import create_app
from app.settings.root import Settings
from fastapi import FastAPI


pytestmark = pytest.mark.unit
DEFAULT_PAGE_LIMIT = 20
MAX_PAGE_LIMIT = 100


@pytest.fixture(scope="module")
def app() -> FastAPI:
    """Build the schema without starting the application lifespan."""
    return create_app(Settings())


def _form_schema(app: FastAPI, path: str) -> dict[str, Any]:
    """Resolve the form schema referenced by one POST operation."""
    operation = cast("dict[str, Any]", app.openapi()["paths"][path]["post"])
    body_schema = operation["requestBody"]["content"][
        "application/x-www-form-urlencoded"
    ]["schema"]
    reference = cast("str", body_schema["$ref"])
    return cast(
        "dict[str, Any]",
        app.openapi()["components"]["schemas"][reference.rsplit("/", 1)[1]],
    )


@pytest.mark.parametrize(
    ("path", "schema_name"),
    [
        ("/management/account", "AccountProfileForm"),
        ("/management/organization", "OrganizationUpdateForm"),
        ("/management/organization/users", "OrganizationUserCreateForm"),
        (
            "/management/organization/users/{user_id}",
            "OrganizationUserReplaceForm",
        ),
        (
            "/management/operator/organizations",
            "OperatorOrganizationCreateForm",
        ),
        (
            "/management/operator/organizations/{organization_id}",
            "OperatorOrganizationUpdateForm",
        ),
        ("/management/operator/users", "ServerUserCreateForm"),
        ("/management/operator/users/{user_id}", "ServerUserReplaceForm"),
        (
            "/management/operator/oauth2/clients",
            "OAuth2ClientRegistrationForm",
        ),
        (
            "/management/operator/oauth2/clients/{client_id}",
            "OAuth2ClientReplacementForm",
        ),
        (
            "/management/operator/oauth2/clients/{client_id}/user-organizations",
            "UserOrganizationForm",
        ),
        (
            "/management/operator/oauth2/clients/{client_id}/machine-organizations",
            "MachineOrganizationForm",
        ),
    ],
)
def test_management_mutations_use_flat_form_models(
    app: FastAPI,
    path: str,
    schema_name: str,
) -> None:
    """Expose each management form directly instead of under a form wrapper."""
    operation = cast("dict[str, Any]", app.openapi()["paths"][path]["post"])
    body_schema = operation["requestBody"]["content"][
        "application/x-www-form-urlencoded"
    ]["schema"]
    assert body_schema["$ref"] == f"#/components/schemas/{schema_name}"

    properties = _form_schema(app, path)["properties"]
    assert "csrf_token" in properties
    assert "form" not in properties


def test_oauth2_client_create_and_replace_forms_have_distinct_fields(
    app: FastAPI,
) -> None:
    """Keep initial organization access out of the replacement transport."""
    create_properties = _form_schema(app, "/management/operator/oauth2/clients")[
        "properties"
    ]
    replace_properties = _form_schema(
        app, "/management/operator/oauth2/clients/{client_id}"
    )["properties"]

    assert "user_organization_access" in create_properties
    assert "organization_ids" in create_properties
    assert "user_organization_access" not in replace_properties
    assert "organization_ids" not in replace_properties


@pytest.mark.parametrize(
    ("path", "required_fields"),
    [
        ("/logout", set()),
        ("/oauth2/authorize/decision", {"transaction_id", "decision"}),
        ("/oauth2/device/verify", {"user_code", "decision"}),
    ],
)
def test_authenticated_browser_forms_document_optional_csrf(
    app: FastAPI,
    path: str,
    required_fields: set[str],
) -> None:
    """Preserve CSRF form documentation after cached-form extraction."""
    schema = _form_schema(app, path)

    assert "csrf_token" in schema["properties"]
    assert set(schema.get("required", [])) == required_fields


@pytest.mark.parametrize(
    ("path", "required_fields", "optional_fields"),
    [
        (
            "/login",
            {"email", "password"},
            {"csrf_token", "transaction_id", "user_code", "return_url"},
        ),
        (
            "/register",
            {"email", "password", "organization_name"},
            {"csrf_token", "first_name", "last_name"},
        ),
        ("/forgot-password", {"email"}, {"csrf_token"}),
        ("/resend-verification", {"email"}, {"csrf_token"}),
        ("/verify-email", {"token"}, {"csrf_token"}),
        ("/reset-password", {"token", "password"}, {"csrf_token"}),
        ("/accept-invite", {"token", "password"}, {"csrf_token"}),
    ],
)
def test_authentication_forms_preserve_flat_fields(
    app: FastAPI,
    path: str,
    required_fields: set[str],
    optional_fields: set[str],
) -> None:
    """Keep browser form names and requiredness through model composition."""
    schema = _form_schema(app, path)
    parts = [schema]
    parts.extend(
        app.openapi()["components"]["schemas"][part["$ref"].rsplit("/", 1)[1]]
        for part in schema.get("allOf", [])
    )
    properties = {key for part in parts for key in part.get("properties", {})}
    required = {key for part in parts for key in part.get("required", [])}

    assert properties == required_fields | optional_fields
    assert required == required_fields


@pytest.mark.parametrize(
    ("path", "filter_names"),
    [
        (
            "/management/operator/users",
            {"q", "organization_id", "role", "operator", "active", "email_verified"},
        ),
        (
            "/management/organization/users",
            {"q", "role", "active", "email_verified", "created_from", "created_to"},
        ),
        (
            "/management/organization/oauth2/sessions",
            {"client_id", "grant_type", "user_id", "active_only"},
        ),
        ("/management/operator/organizations", set()),
        ("/management/operator/oauth2/clients", set()),
    ],
)
def test_management_list_queries_preserve_flat_parameters(
    app: FastAPI, path: str, filter_names: set[str]
) -> None:
    """Expose filters, pagination, and notices as ordinary query parameters."""
    parameters = app.openapi()["paths"][path]["get"]["parameters"]
    query_parameters = {p["name"]: p for p in parameters if p["in"] == "query"}

    assert set(query_parameters) == filter_names | {"offset", "limit", "notice"}
    assert all(not p["required"] for p in query_parameters.values())
    assert query_parameters["offset"]["schema"]["minimum"] == 0
    assert query_parameters["limit"]["schema"]["minimum"] == 1
    assert query_parameters["limit"]["schema"]["maximum"] == MAX_PAGE_LIMIT
    assert query_parameters["limit"]["schema"]["default"] == DEFAULT_PAGE_LIMIT
