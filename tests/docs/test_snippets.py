"""Behavior checks for code displayed in the documentation."""

import importlib.util
import re
import tomllib
from pathlib import Path
from types import ModuleType

import pytest
from app.main import create_app
from app.settings.root import Settings
from app.web.settings import AuthenticationUIMode, UISettings
from fastapi import FastAPI


pytestmark = pytest.mark.unit

ROOT = Path(__file__).parents[2]
SNIPPETS = ROOT / "docs" / "snippets"


def _load_snippet(name: str) -> ModuleType:
    path = SNIPPETS / f"{name}.py"
    spec = importlib.util.spec_from_file_location(f"docs_snippet_{name}", path)
    if spec is None or spec.loader is None:
        msg = f"Could not load documentation snippet: {path}"
        raise RuntimeError(msg)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_minimal_composition_snippet_keeps_browser_authentication() -> None:
    """The minimal server remains authenticatable without OAuth2 protocols."""
    module = _load_snippet("minimal_composition")
    paths = set(module.app.openapi()["paths"])

    assert isinstance(module.app, FastAPI)
    assert module.settings.session.enabled is True
    assert "/register" in paths
    assert "/api/v1/organization/users" in paths
    assert "/login" in paths
    assert "/api/v1/auth/register" not in paths
    assert "/api/v1/sessions/login" not in paths
    assert "/oauth2/token" not in paths
    assert hasattr(module.app.state, "settings")


def test_documented_protocol_routes_match_openapi() -> None:
    """The route reference stays aligned with the canonical server app."""
    settings = Settings(
        ui=UISettings(
            authentication=AuthenticationUIMode.EXTERNAL,
            external_login_url="https://frontend.test/login",
        ),
    )
    paths = set(create_app(settings).openapi()["paths"])

    assert {
        "/oauth2/authorize",
        "/oauth2/token",
        "/oauth2/revoke",
        "/oauth2/introspect",
        "/oauth2/device_authorization",
        "/.well-known/oauth-authorization-server",
        "/.well-known/openid-configuration",
        "/oauth2/jwks.json",
        "/oauth2/userinfo",
    } <= paths


def test_local_markdown_links_resolve() -> None:
    """Repository and documentation links point to existing local files."""
    markdown_files = [
        ROOT / "README.md",
        *sorted((ROOT / "docs").rglob("*.md")),
    ]
    link_pattern = re.compile(r"\[[^]]+\]\(([^)]+)\)")

    for markdown_file in markdown_files:
        for target in link_pattern.findall(markdown_file.read_text()):
            if target.startswith(("http://", "https://", "#", "mailto:")):
                continue
            path_text = target.split("#", maxsplit=1)[0]
            if not path_text:
                continue
            target_path = (markdown_file.parent / path_text).resolve()
            assert target_path.exists(), f"Broken link in {markdown_file}: {target}"


def test_documentation_navigation_targets_resolve() -> None:
    """Every configured documentation navigation target exists."""
    config = tomllib.loads((ROOT / "zensical.toml").read_text())

    def nav_targets(value: object) -> list[str]:
        if isinstance(value, str):
            return [value] if value.endswith(".md") else []
        if isinstance(value, list):
            return [target for item in value for target in nav_targets(item)]
        if isinstance(value, dict):
            return [target for item in value.values() for target in nav_targets(item)]
        return []

    for target in nav_targets(config["project"]["nav"]):
        assert (ROOT / "docs" / target).is_file(), (
            f"Missing documentation navigation target: {target}"
        )
