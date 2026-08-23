"""OpenAPI security schemes and application API security helpers."""

from typing import Any

from fastapi.security import (
    APIKeyCookie,
    HTTPBearer,
    OAuth2AuthorizationCodeBearer,
)

from app.browser_sessions.csrf import CSRF_UNSAFE_METHODS
from app.browser_sessions.enums import CSRFPattern
from app.security.permissions import (
    Permission,
    PERMISSION_DESCRIPTIONS,
)
from app.settings.root import Settings


# Session cookie (Swagger shows a cookie box; login sets the HttpOnly value.)
cookie_sid = APIKeyCookie(name="sessionid", auto_error=False)

# Simple Bearer (paste a JWT)
bearer = HTTPBearer(auto_error=False)


oauth2_auth_code = OAuth2AuthorizationCodeBearer(
    authorizationUrl="/oauth2/authorize",
    tokenUrl="/oauth2/token",
    scopes={
        permission.value: PERMISSION_DESCRIPTIONS[permission]
        for permission in Permission
    },
    auto_error=False,
)


def _filter_disabled_security_schemes(
    schema: dict[str, Any], settings: Settings
) -> None:
    """Remove authentication choices unavailable in this configuration."""
    disabled_schemes: set[str] = set()
    if not settings.session.enabled:
        disabled_schemes.update(
            {"APIKeyCookie", "SessionCSRFHeader", "SessionCSRFCookie"}
        )
    if not settings.oauth2.protocol_enabled:
        disabled_schemes.update(
            {
                "HTTPBearer",
                "OAuth2AuthorizationCode",
                "OAuth2AuthorizationCodeBearer",
                "OAuth2ClientBasic",
            }
        )
    elif not settings.oauth2.authorization_code_enabled:
        disabled_schemes.update(
            {"OAuth2AuthorizationCode", "OAuth2AuthorizationCodeBearer"}
        )
    if not disabled_schemes:
        return

    for path_item in schema.get("paths", {}).values():
        if not isinstance(path_item, dict):
            continue
        for operation in path_item.values():
            if not isinstance(operation, dict):
                continue
            security = operation.get("security")
            if not isinstance(security, list):
                continue
            operation["security"] = [
                requirement
                for requirement in security
                if isinstance(requirement, dict)
                and not disabled_schemes.intersection(requirement)
            ]

    security_schemes = schema.get("components", {}).get("securitySchemes", {})
    if isinstance(security_schemes, dict):
        for scheme_name in disabled_schemes:
            security_schemes.pop(scheme_name, None)


def configure_application_api_security(
    schema: dict[str, Any], settings: Settings
) -> None:
    """Normalize FastAPI-generated application authentication contracts."""
    for path, path_item in schema.get("paths", {}).items():
        if not path.startswith("/api/") or not isinstance(path_item, dict):
            continue
        for method, operation in path_item.items():
            if not isinstance(operation, dict) or "security" not in operation:
                continue
            security_choices: list[dict[str, list[str]]] = []
            for requirement in operation["security"]:
                if not isinstance(requirement, dict):
                    continue
                normalized = {
                    scheme: scopes if scheme == "OAuth2AuthorizationCodeBearer" else []
                    for scheme, scopes in requirement.items()
                }
                if (
                    method.upper() in CSRF_UNSAFE_METHODS
                    and "APIKeyCookie" in normalized
                ):
                    normalized["SessionCSRFHeader"] = []
                    if settings.session.csrf.pattern == CSRFPattern.DOUBLE_SUBMIT:
                        normalized["SessionCSRFCookie"] = []
                if normalized and normalized not in security_choices:
                    security_choices.append(normalized)
            order = {
                "APIKeyCookie": 0,
                "HTTPBearer": 1,
                "OAuth2AuthorizationCodeBearer": 2,
            }
            security_choices.sort(
                key=lambda requirement: min(
                    order.get(scheme, len(order)) for scheme in requirement
                )
            )
            operation["security"] = security_choices

    security_schemes = schema.setdefault("components", {}).setdefault(
        "securitySchemes", {}
    )
    if settings.session.enabled:
        security_schemes["APIKeyCookie"] = {
            "type": "apiKey",
            "in": "cookie",
            "name": settings.session.cookie_name,
        }
        security_schemes["SessionCSRFHeader"] = {
            "type": "apiKey",
            "in": "header",
            "name": settings.session.csrf.header_name,
            "description": (
                "Required with browser-session authentication on state-changing "
                "requests. The server also validates the request Origin or Referer."
            ),
        }
        if settings.session.csrf.pattern == CSRFPattern.DOUBLE_SUBMIT:
            security_schemes["SessionCSRFCookie"] = {
                "type": "apiKey",
                "in": "cookie",
                "name": settings.session.csrf.cookie_name,
                "description": (
                    "Required with the matching CSRF header when double-submit "
                    "browser-session protection is configured."
                ),
            }
    _configure_session_login_csrf(schema, settings)
    _configure_public_session_csrf(schema)
    _configure_session_logout_scope(schema)
    _filter_disabled_security_schemes(schema, settings)


def _configure_session_login_csrf(schema: dict[str, Any], settings: Settings) -> None:
    """Document configurable pre-session CSRF inputs on the JSON login route."""
    path_item = schema.get("paths", {}).get("/api/v1/sessions/login")
    if not isinstance(path_item, dict):
        return
    operation = path_item.get("post")
    if not isinstance(operation, dict):
        return

    parameters = operation.setdefault("parameters", [])
    dynamic_parameters = (
        {
            "name": settings.session.csrf.header_name,
            "in": "header",
            "required": True,
            "description": "Must match the pre-session CSRF cookie.",
            "schema": {"type": "string"},
        },
        {
            "name": settings.session.csrf.cookie_name,
            "in": "cookie",
            "required": True,
            "description": (
                "Pre-session CSRF cookie issued by GET /api/v1/sessions/csrf."
            ),
            "schema": {"type": "string"},
        },
    )
    existing = {
        (parameter.get("name"), parameter.get("in"))
        for parameter in parameters
        if isinstance(parameter, dict)
    }
    parameters.extend(
        parameter
        for parameter in dynamic_parameters
        if (parameter["name"], parameter["in"]) not in existing
    )


def _configure_public_session_csrf(schema: dict[str, Any]) -> None:
    """Keep the optional-cookie CSRF initializer public in OpenAPI."""
    path_item = schema.get("paths", {}).get("/api/v1/sessions/csrf")
    if not isinstance(path_item, dict):
        return
    operation = path_item.get("get")
    if isinstance(operation, dict):
        operation.pop("security", None)


def _configure_session_logout_scope(schema: dict[str, Any]) -> None:
    """Document that the JSON logout scope body is optional."""
    path_item = schema.get("paths", {}).get("/api/v1/sessions/logout")
    if not isinstance(path_item, dict):
        return
    operation = path_item.get("post")
    if not isinstance(operation, dict):
        return
    request_body = operation.get("requestBody")
    if isinstance(request_body, dict):
        request_body["required"] = False
