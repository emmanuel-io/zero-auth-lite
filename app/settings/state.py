"""Stable application-settings state selected during server construction."""

from typing import cast, TYPE_CHECKING


if TYPE_CHECKING:
    from fastapi import FastAPI

    from app.settings.root import Settings


SETTINGS_SNAPSHOT_STATE_KEY = "_settings_snapshot"


def set_settings_snapshot(app: "FastAPI", settings: "Settings") -> None:
    """Store the canonical snapshot and its public inspection alias."""
    setattr(app.state, SETTINGS_SNAPSHOT_STATE_KEY, settings)
    app.state.settings = settings


def get_settings_snapshot(app: "FastAPI") -> "Settings":
    """Return the immutable settings selected by ``create_app``."""
    value = getattr(app.state, SETTINGS_SNAPSHOT_STATE_KEY, None)
    if value is None:
        msg = "App state was not initialized with a settings snapshot."
        raise RuntimeError(msg)
    return cast("Settings", value)
