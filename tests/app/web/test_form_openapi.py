"""OpenAPI contracts for server-rendered form models."""

from typing import Any, cast

import pytest
from app.main import create_app
from app.settings.root import Settings
from fastapi import FastAPI


pytestmark = pytest.mark.unit


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
    create_properties = _form_schema(
        app, "/management/operator/oauth2/clients"
    )["properties"]
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
