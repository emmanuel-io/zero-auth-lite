"""Tests for application version metadata."""

import tomllib

import pytest
from app.version import get_application_version, PROJECT_METADATA_PATH


pytestmark = pytest.mark.unit


def test_application_version_comes_from_project_metadata() -> None:
    """Expose the version declared by pyproject.toml through the application."""
    with PROJECT_METADATA_PATH.open("rb") as metadata_file:
        expected = tomllib.load(metadata_file)["project"]["version"]

    assert get_application_version() == expected
