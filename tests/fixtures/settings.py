"""Explicit helpers for configuring the test application."""

from collections.abc import Callable
from typing import Any

import pytest


def app_settings(**overrides: object) -> Callable[[Any], Any]:
    """Parametrize a test with explicit application setting overrides."""
    return pytest.mark.parametrize(
        "settings_overrides",
        [overrides],
        indirect=True,
    )
