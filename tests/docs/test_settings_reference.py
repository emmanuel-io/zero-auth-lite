"""Tests for settings-reference completeness."""

from pathlib import Path

from app.settings.root import Settings
from pydantic import BaseModel


PROJECT_ROOT = Path(__file__).parents[2]


def _environment_names(model: BaseModel, *, prefix: str) -> set[str]:
    """Return environment names for every leaf in a nested settings model."""
    names: set[str] = set()
    for field_name in type(model).model_fields:
        value = getattr(model, field_name)
        environment_name = f"{prefix}{field_name.upper()}"
        if isinstance(value, BaseModel):
            names.update(_environment_names(value, prefix=f"{environment_name}__"))
        else:
            names.add(environment_name)
    return names


def _setting_paths(model: BaseModel, *, prefix: str = "") -> set[str]:
    """Return dotted TOML paths for every leaf in a settings model."""
    paths: set[str] = set()
    for field_name in type(model).model_fields:
        value = getattr(model, field_name)
        path = f"{prefix}.{field_name}" if prefix else field_name
        if isinstance(value, BaseModel):
            paths.update(_setting_paths(value, prefix=path))
        else:
            paths.add(path)
    return paths


def _documented_toml_paths(profile: str) -> set[str]:
    """Read active and commented setting assignments from a TOML example."""
    section = ""
    paths: set[str] = set()
    for raw_line in profile.splitlines():
        line = raw_line.removeprefix("#").strip()
        if line.startswith("[") and line.endswith("]"):
            section = line.removeprefix("[").removesuffix("]")
        elif "=" in line:
            field_name = line.split("=", maxsplit=1)[0].strip()
            path = f"{section}.{field_name}" if section else field_name
            paths.add(path)
    return paths


def test_settings_reference_names_every_environment_setting() -> None:
    """Keep the settings reference complete as configuration grows."""
    documented = (PROJECT_ROOT / "docs/reference/settings.md").read_text()
    expected = _environment_names(Settings(), prefix="ZA_")

    assert expected <= set(documented.split("`"))


def test_toml_examples_name_every_setting() -> None:
    """Keep both executable TOML references complete."""
    expected = _setting_paths(Settings())

    for filename in (
        "config/full-server.example.toml",
        "config/development.example.toml",
    ):
        profile = (PROJECT_ROOT / filename).read_text()
        documented = _documented_toml_paths(profile)
        assert documented == expected, filename
