"""Tests for settings-reference completeness."""

import json
import re
import tomllib
from enum import Enum
from pathlib import Path
from typing import Any

from app.settings.root import Settings
from app.workflow_tokens.settings import DEFAULT_WORKFLOW_TOKEN_DERIVATION_SECRET
from pydantic import BaseModel, SecretStr, TypeAdapter


PROJECT_ROOT = Path(__file__).parents[2]
SEMANTIC_NON_NULL_DEFAULTS = {
    "development key",
    "development value",
    "local auth origin",
    "local built-in device URL",
    "local built-in invitation URL",
    "local built-in reset URL",
    "local built-in verification URL",
    "local HTTPS auth origin",
    "local origins",
}


def _environment_values(model: BaseModel, *, prefix: str) -> dict[str, object]:
    """Return environment names and defaults for nested settings leaves."""
    values: dict[str, object] = {}
    for field_name in type(model).model_fields:
        value = getattr(model, field_name)
        environment_name = f"{prefix}{field_name.upper()}"
        if isinstance(value, BaseModel):
            values.update(_environment_values(value, prefix=f"{environment_name}__"))
        else:
            values[environment_name] = value
    return values


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


def _documented_environment_settings() -> dict[str, tuple[str, str]]:
    """Parse environment setting, default, and purpose table rows."""
    documented: dict[str, tuple[str, str]] = {}
    markdown = (PROJECT_ROOT / "docs/reference/settings.md").read_text()
    for line in markdown.splitlines():
        match = re.fullmatch(
            r"\| `(?P<name>ZA_[A-Z0-9_]+)` \| (?P<default>.*?) \| (?P<purpose>.+) \|",
            line,
        )
        if match is None:
            continue
        documented[match.group("name")] = (
            match.group("default").strip().strip("`"),
            match.group("purpose").strip(),
        )
    return documented


def _float_default_matches(value: float, documented: str) -> bool:
    """Compare a documented string with a floating-point default."""
    try:
        return float(documented) == value
    except ValueError:
        return False


def _sequence_default_matches(
    value: tuple[object, ...] | list[object], documented: str
) -> bool:
    """Compare a documented JSON array with a sequence default."""
    try:
        return bool(list(value) == json.loads(documented))
    except json.JSONDecodeError:
        return False


def _default_matches(value: object, documented: str) -> bool:
    """Compare concrete defaults while recognizing explicit semantic labels."""
    if documented in {"unset", "packaged templates"}:
        return value is None
    if documented == "empty":
        return value in ("", (), [])
    if documented in SEMANTIC_NON_NULL_DEFAULTS:
        return value is not None
    if isinstance(value, SecretStr):
        value = value.get_secret_value()
    if isinstance(value, Enum):
        value = value.value
    if isinstance(value, bool):
        matches = documented == str(value).lower()
    elif isinstance(value, float):
        matches = _float_default_matches(value, documented)
    elif isinstance(value, Path):
        matches = Path(documented) == value
    elif isinstance(value, (tuple, list)):
        matches = _sequence_default_matches(value, documented)
    else:
        matches = documented == str(value)
    return matches


def _profile_values(profile: str) -> dict[str, Any]:
    """Parse active and commented example assignments as one typed profile."""
    parseable: list[str] = []
    for raw_line in profile.splitlines():
        line = raw_line.strip()
        if line.startswith("[") and line.endswith("]"):
            parseable.append(line)
            continue
        assignment = re.fullmatch(r"(?:#\s*)?([a-z][a-z0-9_]*)\s*=\s*(.+)", line)
        if assignment is not None:
            parseable.append(f"{assignment.group(1)} = {assignment.group(2)}")
    return tomllib.loads("\n".join(parseable))


def _validate_profile_values(values: dict[str, Any], model: BaseModel) -> None:
    """Validate every example value against its owning settings field type."""
    for field_name, value in values.items():
        field = type(model).model_fields[field_name]
        current = getattr(model, field_name)
        if isinstance(current, BaseModel):
            assert isinstance(value, dict)
            _validate_profile_values(value, current)
        else:
            TypeAdapter(field.annotation).validate_python(value)


def test_settings_reference_matches_environment_names_and_defaults() -> None:
    """Keep documented names, defaults, and purposes aligned with settings."""
    expected = _environment_values(Settings.model_construct(), prefix="ZA_")
    documented = _documented_environment_settings()

    assert documented.keys() == expected.keys()
    mismatches = {
        name: (default, value)
        for name, value in expected.items()
        if not _default_matches(value, (default := documented[name][0]))
    }
    assert not mismatches, mismatches
    assert all(purpose for _, purpose in documented.values())


def test_toml_examples_name_every_setting() -> None:
    """Keep both executable TOML references complete."""
    defaults = Settings.model_construct()
    expected = _setting_paths(defaults)

    for filename in (
        "config/full-server.example.toml",
        "config/development.example.toml",
    ):
        profile = (PROJECT_ROOT / filename).read_text()
        documented = _documented_toml_paths(profile)
        assert documented == expected, filename
        _validate_profile_values(_profile_values(profile), defaults)


def test_development_profile_names_the_actual_workflow_token_secret_default() -> None:
    """Keep the commented workflow-token secret aligned with its code default."""
    profile = (PROJECT_ROOT / "config/development.example.toml").read_text()

    assert (
        f'# derivation_secret = "{DEFAULT_WORKFLOW_TOKEN_DERIVATION_SECRET}"' in profile
    )
