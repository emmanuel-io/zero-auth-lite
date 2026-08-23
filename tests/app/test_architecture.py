"""Tests for server feature-module boundaries."""

import ast
from pathlib import Path

import pytest


pytestmark = pytest.mark.unit

APP = Path(__file__).parents[2] / "app"
CANONICAL_PRINCIPAL_CLASSES = {
    "AuthMethod",
    "PrincipalContext",
    "UserPrincipalContext",
    "BrowserUserPrincipalContext",
    "OAuth2UserPrincipalContext",
    "OAuth2ClientPrincipalContext",
}
CANONICAL_PRINCIPAL_ALIASES = {
    "AuthenticatedPrincipalContext",
    "OAuth2PrincipalContext",
}


def _imported_modules(module_path: Path) -> set[str]:
    """Return absolute modules imported by one Python source file."""
    tree = ast.parse(module_path.read_text(), filename=str(module_path))
    imported_modules: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module is not None:
            imported_modules.add(node.module)
        if isinstance(node, ast.Import):
            imported_modules.update(alias.name for alias in node.names)
    return imported_modules


def test_authentication_principal_has_one_canonical_definition() -> None:
    """Prevent parallel authentication-principal models from returning."""
    definitions: dict[str, list[Path]] = {
        class_name: [] for class_name in CANONICAL_PRINCIPAL_CLASSES
    }
    for module_path in APP.rglob("*.py"):
        tree = ast.parse(module_path.read_text(), filename=str(module_path))
        for node in ast.walk(tree):
            if isinstance(node, ast.ClassDef) and node.name in definitions:
                definitions[node.name].append(module_path)

    canonical_module = APP / "security" / "dtos.py"
    assert definitions == {
        class_name: [canonical_module] for class_name in CANONICAL_PRINCIPAL_CLASSES
    }
    tree = ast.parse(canonical_module.read_text(), filename=str(canonical_module))
    aliases = {
        node.name.id
        for node in ast.walk(tree)
        if isinstance(node, ast.TypeAlias)
        and isinstance(node.name, ast.Name)
        and node.name.id in CANONICAL_PRINCIPAL_ALIASES
    }
    assert aliases == CANONICAL_PRINCIPAL_ALIASES


def test_oauth2_service_returns_framework_light_authorization_results() -> None:
    """Assert OAuth2 services do not import Starlette response objects."""
    service_paths = (
        APP / "oauth2" / "authorization" / "request.py",
        APP / "oauth2" / "authorization" / "code_exchange.py",
        APP / "oauth2" / "authorization" / "result.py",
        APP / "oauth2" / "validation.py",
    )
    imported_modules: set[str] = set()
    for service_path in service_paths:
        tree = ast.parse(service_path.read_text(), filename=str(service_path))
        imported_modules.update(
            node.module
            for node in ast.walk(tree)
            if isinstance(node, ast.ImportFrom) and node.module is not None
        )

    assert "starlette.responses" not in imported_modules
    assert "app.oauth2.authorization.result" in imported_modules


def test_non_api_features_do_not_import_the_api_transport_layer() -> None:
    """Keep versioned HTTP contracts inside their owning API package."""
    api_root = APP / "api"
    main_module = APP / "main.py"
    assert APP.is_dir(), APP
    assert api_root.is_dir(), api_root
    assert main_module.is_file(), main_module

    for module_path in APP.rglob("*.py"):
        if module_path == main_module or module_path.is_relative_to(api_root):
            continue
        imported_modules = _imported_modules(module_path)
        assert not any(
            module == "app.api" or module.startswith("app.api.")
            for module in imported_modules
        ), module_path


def test_core_does_not_compose_authentication_features() -> None:
    """Keep session and OAuth2 composition in the application security layer."""
    feature_prefixes = (
        "app.browser_sessions",
        "app.oauth2",
        "app.security",
    )
    core_root = APP / "core"
    assert core_root.is_dir(), core_root

    for module_path in core_root.rglob("*.py"):
        imported_modules = _imported_modules(module_path)
        assert not any(
            module == prefix or module.startswith(f"{prefix}.")
            for module in imported_modules
            for prefix in feature_prefixes
        ), module_path
