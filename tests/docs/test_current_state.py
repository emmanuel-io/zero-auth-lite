"""Tests that keep documentation aligned with the current checkout."""

import re
import tomllib
from collections.abc import Iterable
from pathlib import Path

from app.browser_sessions.settings import BrowserSessionSettings
from app.main import create_app
from app.oauth2.settings import OAuth2Settings
from app.settings.api import APISettings
from app.settings.identity_workflow import IdentityWorkflowSettings
from app.settings.root import Settings
from app.settings.ui import (
    IdentityWorkflowUIMode,
    ManagementAuthenticationMode,
    OAuth2InteractionUIMode,
    UISettings,
)


PROJECT_ROOT = Path(__file__).parents[2]
HTTP_METHODS = {"DELETE", "GET", "PATCH", "POST", "PUT"}


def _navigation_paths(items: list[dict[str, object]]) -> set[str]:
    """Return every Markdown target in a nested Zensical navigation list."""
    paths: set[str] = set()
    for item in items:
        for value in item.values():
            if isinstance(value, str):
                paths.add(value)
            elif isinstance(value, list):
                paths.update(_navigation_paths(value))
    return paths


def _route_entries(routes: Iterable[object]) -> set[tuple[str, str]]:
    """Return explicit HTTP method and path pairs for application routes."""
    entries: set[tuple[str, str]] = set()
    for route in routes:
        path = getattr(route, "path", "")
        methods = set(getattr(route, "methods", set()) or set()) & HTTP_METHODS
        entries.update((method, path) for method in methods if path)
    return entries


def _application_routes(app: object) -> set[tuple[str, str]]:
    """Return direct and lazily included application route contracts."""
    entries: set[tuple[str, str]] = set()
    for route in getattr(app, "routes", []):
        entries.update(_route_entries((route,)))
        effective_route_contexts = getattr(route, "effective_route_contexts", None)
        if callable(effective_route_contexts):
            entries.update(_route_entries(effective_route_contexts()))
    return entries


def _markdown_tables(markdown: str) -> list[tuple[list[str], list[list[str]]]]:
    """Parse simple pipe-delimited Markdown tables without accepting prose."""
    lines = markdown.splitlines()
    tables: list[tuple[list[str], list[list[str]]]] = []
    index = 0
    while index + 1 < len(lines):
        header_line = lines[index].strip()
        separator_line = lines[index + 1].strip()
        if not header_line.startswith("|") or not re.fullmatch(
            r"\|(?:\s*:?-+:?\s*\|)+", separator_line
        ):
            index += 1
            continue
        headers = [cell.strip() for cell in header_line.strip("|").split("|")]
        rows: list[list[str]] = []
        index += 2
        while index < len(lines) and lines[index].strip().startswith("|"):
            rows.append(
                [cell.strip() for cell in lines[index].strip().strip("|").split("|")]
            )
            index += 1
        tables.append((headers, rows))
    return tables


def _documented_routes(markdown: str) -> set[tuple[str, str]]:
    """Return method and path pairs from route-reference contract tables."""
    entries: set[tuple[str, str]] = set()
    for headers, rows in _markdown_tables(markdown):
        if headers[:2] != ["Method", "Path"]:
            continue
        for row in rows:
            methods = {
                value.strip().strip("`") for value in row[0].split(",") if value.strip()
            }
            path = row[1].strip("`")
            assert methods <= HTTP_METHODS, (methods, path)
            entries.update((method, path) for method in methods)
    return entries


def _route_settings_variants() -> tuple[Settings, ...]:
    """Cover every settings-selected route family in the reference."""
    external_ui = UISettings(
        identity_workflow_mode=IdentityWorkflowUIMode.EXTERNAL,
        management_authentication=ManagementAuthenticationMode.EXTERNAL,
        oauth2_interaction=OAuth2InteractionUIMode.EXTERNAL,
        urls={
            "login": "https://frontend.example/login",
            "logout": "https://frontend.example/logout",
            "verification": "https://frontend.example/verify",
            "password_reset": "https://frontend.example/reset",
            "invitation": "https://frontend.example/invite",
            "authorization_interaction": "https://frontend.example/oauth2/authorize",
            "device_interaction": "https://frontend.example/oauth2/device",
        },
    )
    return (
        Settings.model_construct(),
        Settings.model_construct(ui=external_ui),
        Settings.model_construct(
            ui=UISettings(identity_workflow_mode=IdentityWorkflowUIMode.DISABLED),
        ),
        Settings.model_construct(
            api=APISettings(interactive_auth_routes_enabled=False),
            identity_workflow=IdentityWorkflowSettings(registration_enabled=False),
            browser_session=BrowserSessionSettings(enabled=False),
            oauth2=OAuth2Settings().model_copy(
                update={
                    "authorization_code_enabled": False,
                    "device_code_enabled": False,
                    "oidc_enabled": False,
                    "refresh_token_enabled": False,
                }
            ),
            ui=UISettings(
                identity_workflow_mode=IdentityWorkflowUIMode.DISABLED,
                oauth2_interaction=OAuth2InteractionUIMode.DISABLED,
            ),
        ),
    )


def test_every_documentation_page_is_in_navigation() -> None:
    """Keep the site structure complete and every page discoverable."""
    config = tomllib.loads((PROJECT_ROOT / "zensical.toml").read_text())
    navigation = _navigation_paths(config["project"]["nav"])
    markdown_pages = {
        str(path.relative_to(PROJECT_ROOT / "docs"))
        for path in (PROJECT_ROOT / "docs").rglob("*.md")
    }

    assert navigation == markdown_pages


def test_documented_source_paths_exist() -> None:
    """Reject stale source paths in the README and documentation."""
    markdown_files = [PROJECT_ROOT / "README.md", *PROJECT_ROOT.glob("docs/**/*.md")]
    missing: list[str] = []

    for markdown_file in markdown_files:
        text = markdown_file.read_text()
        for match in re.finditer(
            r"`((?:app|tests|docs|scripts|alembic)/[\w./-]+)`", text
        ):
            source_path = PROJECT_ROOT / match.group(1)
            if not source_path.exists():
                line = text[: match.start()].count("\n") + 1
                missing.append(
                    f"{markdown_file.relative_to(PROJECT_ROOT)}:{line}: "
                    f"{match.group(1)}"
                )

    assert not missing, "\n".join(missing)


def test_canonical_launchers_leave_proxy_trust_to_the_application() -> None:
    """Keep request.client raw for the application-owned trusted-proxy policy."""
    launcher_files = (
        PROJECT_ROOT / "README.md",
        PROJECT_ROOT / "docs/getting-started/installation.md",
        PROJECT_ROOT / "docs/development/setup.md",
        PROJECT_ROOT / "docs/operations/deployment.md",
    )
    for launcher_file in launcher_files:
        for line in launcher_file.read_text().splitlines():
            if "uv run uvicorn" in line:
                assert "--no-proxy-headers" in line, launcher_file

    dockerfile = (PROJECT_ROOT / "docker/Dockerfile").read_text()
    assert '"--no-proxy-headers"' in dockerfile
    deployment = (PROJECT_ROOT / "docs/operations/deployment.md").read_text()
    assert "--forwarded-allow-ips ''" in deployment


def test_route_reference_matches_every_supported_route_contract() -> None:
    """Reject missing, stale, or incorrectly methoded route-reference rows."""
    documented = _documented_routes(
        (PROJECT_ROOT / "docs/reference/routes.md").read_text()
    )
    mounted = {
        entry
        for settings in _route_settings_variants()
        for entry in _application_routes(create_app(settings))
    }

    assert documented == mounted


def test_route_reference_profiles_cover_conditional_mounting() -> None:
    """Exercise each settings boundary represented by the startup matrix."""
    builtin, external, headless, machine = (
        _application_routes(create_app(settings))
        for settings in _route_settings_variants()
    )

    assert ("GET", "/login") in builtin
    assert ("GET", "/consent") in builtin
    authorization_interaction = (
        "POST",
        "/api/v1/oauth2/authorization-interactions/{transaction_id}",
    )
    assert authorization_interaction not in builtin

    assert ("GET", "/login") not in external
    assert ("GET", "/consent") not in external
    assert authorization_interaction in external
    assert ("GET", "/management") in external

    assert ("GET", "/register") not in headless
    assert ("POST", "/api/v1/auth/register") in headless

    assert ("POST", "/api/v1/sessions/login") not in machine
    assert ("POST", "/api/v1/auth/register") not in machine
    assert ("GET", "/management") not in machine
    assert ("POST", "/oauth2/token") in machine


def test_composition_reference_names_top_level_settings_ownership() -> None:
    """Keep the composition overview aligned with the root settings shape."""
    documented = (PROJECT_ROOT / "docs/development/composition.md").read_text()

    for field_name in Settings.model_fields:
        assert f"`{field_name}`" in documented


def test_migration_operations_target_head_without_pinning_initial_revision() -> None:
    """Keep deployment guidance valid as the Alembic chain grows."""
    documented = (PROJECT_ROOT / "docs/operations/migrations.md").read_text()

    assert "alembic upgrade head" in documented
    assert "must not\nhard-code that revision identifier" in documented
    assert "only the initial revision does not satisfy" not in documented
