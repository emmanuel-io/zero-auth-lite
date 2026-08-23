"""Pytest entrypoint for shared test fixtures."""

from pathlib import Path

import pytest


pytest_plugins = [
    "tests.fixtures.app",
    "tests.fixtures.session",
]


@pytest.fixture(autouse=True)
def isolate_settings_config(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """Prevent developer-local settings files from affecting tests."""
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("ZA_CONFIG_FILE", raising=False)
