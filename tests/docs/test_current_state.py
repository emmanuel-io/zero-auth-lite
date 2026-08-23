"""Tests that keep documentation aligned with the current checkout."""

import re
import tomllib
from pathlib import Path

from app.main import create_app
from app.settings.root import Settings
from app.web.settings import AuthenticationUIMode, UISettings


PROJECT_ROOT = Path(__file__).parents[2]


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


def test_route_reference_names_every_openapi_path() -> None:
    """Cover built-in and external transport paths in the route reference."""
    documented = (PROJECT_ROOT / "docs/reference/routes.md").read_text()
    settings_variants = (
        Settings(),
        Settings(
            ui=UISettings(
                authentication=AuthenticationUIMode.EXTERNAL,
                external_login_url="https://frontend.example/login",
            ),
        ),
    )

    paths = {
        path
        for settings in settings_variants
        for path in create_app(settings).openapi()["paths"]
    }

    missing = {path for path in paths if path not in documented}
    assert not missing, missing


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
