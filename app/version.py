"""Application version sourced from the project metadata."""

import tomllib
from pathlib import Path


PROJECT_METADATA_PATH = Path(__file__).parents[1] / "pyproject.toml"


def get_application_version() -> str:
    """Return the version declared by the canonical project metadata."""
    with PROJECT_METADATA_PATH.open("rb") as metadata_file:
        project = tomllib.load(metadata_file).get("project")
    version = project.get("version") if isinstance(project, dict) else None
    if not isinstance(version, str):
        msg = "pyproject.toml must declare project.version"
        raise TypeError(msg)
    return version
