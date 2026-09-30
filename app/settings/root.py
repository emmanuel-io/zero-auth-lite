"""Application settings for the canonical Zero Auth Lite server."""

from __future__ import annotations

import os
from pathlib import Path

from pydantic import AnyHttpUrl, model_validator
from pydantic_settings import (
    BaseSettings,
    PydanticBaseSettingsSource,
    SettingsConfigDict,
    SettingsError,
    TomlConfigSettingsSource,
)

from app.bootstrap.settings import BootstrapSettings
from app.browser_sessions.settings import BrowserSessionSettings
from app.mail.settings import MailSettings
from app.notifications.settings import NotificationOutboxSettings
from app.oauth2.settings import OAuth2Settings
from app.settings.api import APISettings
from app.settings.app import AppSettings
from app.settings.cors import CorsSettings
from app.settings.deployment_validation import validate_deployment_settings
from app.settings.identity_workflow import IdentityWorkflowSettings
from app.settings.topology_validation import (
    validate_authentication_available,
    validate_feature_topology,
)
from app.settings.ui import UISettings
from app.settings.ui_validation import validate_ui_urls


CONFIG_FILE_ENVIRONMENT_VARIABLE = "ZA_CONFIG_FILE"
DEFAULT_CONFIG_FILE = Path("zero-auth-lite.toml")
UNSUPPORTED_ENVIRONMENT_PREFIXES = ("ZA_AUTH__", "ZA_SESSION__")
UNSUPPORTED_ENVIRONMENT_NAMES = frozenset(
    {
        "ZA_API__BROWSER_FLOWS_ENABLED",
        "ZA_API__BROWSER_TRANSPORT_ENABLED",
        "ZA_UI__IDENTITY_WORKFLOW",
        "ZA_SNOWFLAKE_NODE_ID",
    }
)


def _reject_unsupported_environment_names() -> None:
    """Reject superseded configuration names instead of ignoring them."""
    unsupported = sorted(
        name
        for name in os.environ
        if name in UNSUPPORTED_ENVIRONMENT_NAMES
        or name.startswith(UNSUPPORTED_ENVIRONMENT_PREFIXES)
    )
    if unsupported:
        msg = "Unsupported configuration environment variables: " + ", ".join(
            unsupported
        )
        raise SettingsError(msg)


def _config_file_path() -> Path:
    """Return the selected TOML path and validate explicit selections."""
    configured_path = os.environ.get(CONFIG_FILE_ENVIRONMENT_VARIABLE)
    if configured_path is None:
        return DEFAULT_CONFIG_FILE
    if not configured_path.strip():
        msg = f"{CONFIG_FILE_ENVIRONMENT_VARIABLE} must not be empty"
        raise SettingsError(msg)
    path = Path(configured_path)
    if not path.is_file():
        msg = f"{CONFIG_FILE_ENVIRONMENT_VARIABLE} does not name a file: {path}"
        raise SettingsError(msg)
    return path


class DatabaseSettings(BaseSettings):
    """Database-only settings for schema-management commands."""

    model_config = SettingsConfigDict(
        env_prefix="ZA_",
        extra="ignore",
        frozen=True,
    )

    @classmethod
    def settings_customise_sources(
        cls,
        settings_cls: type[BaseSettings],
        init_settings: PydanticBaseSettingsSource,
        env_settings: PydanticBaseSettingsSource,
        dotenv_settings: PydanticBaseSettingsSource,
        file_secret_settings: PydanticBaseSettingsSource,
    ) -> tuple[PydanticBaseSettingsSource, ...]:
        """Load database values without validating unrelated server settings."""
        del cls, dotenv_settings, file_secret_settings
        return (
            init_settings,
            env_settings,
            TomlConfigSettingsSource(settings_cls, toml_file=_config_file_path()),
        )

    db_path: Path = Path("./data/zero-auth-lite.db")
    db_echo: bool = False


class Settings(BaseSettings):
    """Root settings for the runnable Zero Auth Lite server."""

    model_config = SettingsConfigDict(
        env_prefix="ZA_",
        env_nested_delimiter="__",
        extra="forbid",
        frozen=True,
        nested_model_default_partial_update=True,
        populate_by_name=True,
    )

    @classmethod
    def settings_customise_sources(
        cls,
        settings_cls: type[BaseSettings],
        init_settings: PydanticBaseSettingsSource,
        env_settings: PydanticBaseSettingsSource,
        dotenv_settings: PydanticBaseSettingsSource,
        file_secret_settings: PydanticBaseSettingsSource,
    ) -> tuple[PydanticBaseSettingsSource, ...]:
        """Load explicit values, environment overrides, then TOML settings."""
        del cls, dotenv_settings, file_secret_settings
        _reject_unsupported_environment_names()
        return (
            init_settings,
            env_settings,
            TomlConfigSettingsSource(settings_cls, toml_file=_config_file_path()),
        )

    app: AppSettings = AppSettings()
    runtime_dir: Path = Path("/tmp/zero-auth-lite")  # noqa: S108
    db_path: Path = Path("./data/zero-auth-lite.db")
    db_echo: bool = False
    default_redirect_url: AnyHttpUrl | None = None
    api: APISettings = APISettings()
    cors: CorsSettings = CorsSettings()
    oauth2: OAuth2Settings = OAuth2Settings()
    identity_workflow: IdentityWorkflowSettings = IdentityWorkflowSettings()
    notification_outbox: NotificationOutboxSettings = NotificationOutboxSettings()
    bootstrap: BootstrapSettings = BootstrapSettings()
    mail: MailSettings = MailSettings()
    browser_session: BrowserSessionSettings = BrowserSessionSettings()
    ui: UISettings = UISettings()

    @model_validator(mode="after")
    def validate_combined_settings(self) -> Settings:
        """Reject invalid combinations before the server starts."""
        validate_feature_topology(self)
        validate_ui_urls(self)
        self.oauth2.validate_startup_key_material()
        if self.app.environment == "deployment":
            validate_deployment_settings(self)
        validate_authentication_available(self)
        return self


def load_settings() -> Settings:
    """Load application settings from TOML and environment overrides."""
    return Settings()


def load_database_settings() -> DatabaseSettings:
    """Load only the settings required to migrate the SQLite schema."""
    return DatabaseSettings()
