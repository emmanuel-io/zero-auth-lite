"""Pytest entrypoint for black-box route tests."""

from tests.fixtures.routes import (  # noqa: F401
    app,
    browser_client_factory,
    client,
    migrated_database_template,
    settings_overrides,
    verified_user_credentials,
)
