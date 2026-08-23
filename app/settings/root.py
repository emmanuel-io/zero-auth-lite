"""Application settings for the canonical Zero Auth Lite server."""

from __future__ import annotations

import os
from ipaddress import ip_address, ip_network
from pathlib import Path
from urllib.parse import urlsplit

from pydantic import AnyHttpUrl, Field, model_validator
from pydantic_settings import (
    BaseSettings,
    PydanticBaseSettingsSource,
    SettingsConfigDict,
    SettingsError,
    TomlConfigSettingsSource,
)

from app.auth_tokens.settings import DEFAULT_AUTH_TOKEN_DERIVATION_SECRET
from app.bootstrap.settings import BootstrapSettings
from app.browser_sessions.settings import (
    DEFAULT_SESSION_ID_HASH_SECRET,
    SessionSettings,
)
from app.db.snowflake import SNOWFLAKE_MAX_NODE_ID
from app.events.settings import EventOutboxSettings
from app.mail.settings import MailSettings
from app.oauth2.settings import (
    DEFAULT_AUTHORIZATION_CODE_HASH_SECRET,
    DEFAULT_TOKEN_HASH_SECRET,
    OAuth2Settings,
)
from app.settings.app import AppSettings
from app.settings.auth import AuthSettings
from app.settings.cors import CorsSettings
from app.settings.defaults import DEV_OAUTH2_PRIVATE_KEY_B64, DEV_OAUTH2_PUBLIC_KEY_B64
from app.settings.origins import validate_absolute_http_origin
from app.web.settings import UISettings


EXAMPLE_SECRET_PLACEHOLDER = "replace-with-at-least-32-random-characters"
CONFIG_FILE_ENVIRONMENT_VARIABLE = "ZA_CONFIG_FILE"
DEFAULT_CONFIG_FILE = Path("zero-auth-lite.toml")


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
        return (
            init_settings,
            env_settings,
            TomlConfigSettingsSource(settings_cls, toml_file=_config_file_path()),
        )

    app: AppSettings = AppSettings()
    runtime_dir: Path = Path("/tmp/zero-auth-lite")  # noqa: S108
    snowflake_node_id: int | None = Field(default=None, ge=0, le=SNOWFLAKE_MAX_NODE_ID)
    db_path: Path = Path("./data/zero-auth-lite.db")
    db_echo: bool = False
    default_redirect_url: AnyHttpUrl | None = None
    cors: CorsSettings = CorsSettings()
    oauth2: OAuth2Settings = OAuth2Settings()
    auth: AuthSettings = AuthSettings()
    events: EventOutboxSettings = EventOutboxSettings()
    bootstrap: BootstrapSettings = BootstrapSettings()
    mail: MailSettings = MailSettings()
    session: SessionSettings = SessionSettings()
    ui: UISettings = UISettings()

    @model_validator(mode="after")
    def validate_combined_settings(self) -> Settings:
        """Reject invalid combinations before the server starts."""
        if not self.session.enabled:
            if self.oauth2.oidc_enabled:
                msg = "OpenID Connect support requires browser sessions."
                raise ValueError(msg)
            if self.oauth2.authorization_code_enabled:
                msg = "OAuth2 authorization code support requires browser sessions."
                raise ValueError(msg)
            if self.oauth2.device_code_enabled:
                msg = "OAuth2 device code support requires browser sessions."
                raise ValueError(msg)
        if (
            self.oauth2.device_code_enabled
            and not self.ui.oauth2_interaction_is_builtin
        ):
            msg = "OAuth2 device code support requires the built-in UI."
            raise ValueError(msg)
        interactive_login_required = self.ui.oauth2_interaction_is_builtin and (
            self.oauth2.authorization_code_enabled or self.oauth2.device_code_enabled
        )
        if (
            interactive_login_required
            and not self.ui.authentication_is_builtin
            and self.ui.external_login_url is None
        ):
            msg = (
                "Interactive OAuth2 flows require ui.external_login_url when "
                "ui.authentication is external."
            )
            raise ValueError(msg)
        if self.ui.external_login_url is not None:
            external_login = urlsplit(str(self.ui.external_login_url))
            if (
                external_login.username is not None
                or external_login.password is not None
                or external_login.query
                or external_login.fragment
            ):
                msg = (
                    "ui.external_login_url must be an absolute HTTP(S) URL without "
                    "credentials, query string, or fragment"
                )
                raise ValueError(msg)

        self.oauth2.validate_startup_key_material()

        if self.app.environment == "deployment":
            self._validate_deployment_settings()

        if not self.session.enabled and not self.oauth2.has_enabled_grants:
            msg = (
                "At least one authentication mechanism must remain enabled: "
                "browser sessions or an OAuth2 grant"
            )
            raise ValueError(msg)
        return self

    @staticmethod
    def _validate_absolute_origin(*, name: str, value: str) -> None:
        """Require an exact absolute HTTP(S) origin without URL components."""
        validate_absolute_http_origin(name=name, value=value)

    @staticmethod
    def _is_local_hostname(hostname: str | None) -> bool:
        """Return whether a hostname belongs to a local-only topology."""
        if hostname is None:
            return False
        normalized = hostname.rstrip(".").casefold()
        if normalized == "localhost" or normalized.endswith(".localhost"):
            return True
        try:
            return ip_address(normalized).is_loopback
        except ValueError:
            return False

    @classmethod
    def _reject_local_url(cls, *, name: str, value: str) -> None:
        """Reject an absolute URL whose host is usable only for local examples."""
        if cls._is_local_hostname(urlsplit(value).hostname):
            msg = f"Deployment mode rejects local-only host in {name}"
            raise ValueError(msg)

    @classmethod
    def _validate_deployment_origin(cls, *, name: str, value: str) -> None:
        """Require one exact, non-local HTTPS origin for deployment."""
        cls._validate_absolute_origin(name=name, value=value)
        if urlsplit(value).scheme != "https":
            msg = f"Deployment mode requires HTTPS in {name}"
            raise ValueError(msg)
        cls._reject_local_url(name=name, value=value)

    def _validate_deployment_cors(self) -> None:
        """Require configured CORS origins to describe a non-local topology."""
        if not self.cors.enabled:
            return
        for origin in self.cors.allowed_origins:
            self._validate_deployment_origin(
                name="cors.allowed_origins",
                value=origin,
            )

    def _validate_deployment_network_inputs(self) -> None:
        """Reject ineffective host checks and malformed trusted proxy networks."""
        invalid_hosts = [
            host
            for host in self.app.trusted_hosts
            if not host.strip() or host.strip() == "*"
        ]
        if invalid_hosts:
            msg = "Deployment mode requires restrictive trusted_hosts"
            raise ValueError(msg)
        for network in self.app.trusted_proxy_ips:
            try:
                ip_network(network, strict=False)
            except ValueError as exc:
                msg = "app.trusted_proxy_ips must contain valid IP networks"
                raise ValueError(msg) from exc

    def _validate_deployment_session_topology(self) -> None:
        """Require secure, non-local browser-session and CSRF settings."""
        if not self.session.enabled:
            return
        if not self.session.cookie_secure:
            msg = "Deployment mode requires secure browser-session cookies"
            raise ValueError(msg)
        if not self.session.csrf.cookie_secure:
            msg = "Deployment mode requires secure CSRF cookies"
            raise ValueError(msg)
        cookie_domains = {
            "session.cookie_domain": self.session.cookie_domain,
            "session.csrf.cookie_domain": self.session.csrf.cookie_domain,
        }
        for name, domain in cookie_domains.items():
            if domain and self._is_local_hostname(domain.lstrip(".")):
                msg = f"Deployment mode rejects local-only host in {name}"
                raise ValueError(msg)
        csrf_origins = {
            "session.csrf.trusted_origins": self.session.csrf.trusted_origins,
        }
        if self.session.csrf.public_origin is not None:
            csrf_origins["session.csrf.public_origin"] = (
                self.session.csrf.public_origin,
            )
        for name, origins in csrf_origins.items():
            for origin in origins:
                self._validate_deployment_origin(name=name, value=origin)

    def _validate_deployment_public_urls(self) -> None:
        """Require HTTPS and non-local OAuth2 and workflow public URLs."""
        if self.oauth2.protocol_enabled:
            if urlsplit(self.oauth2.jwt_issuer).scheme != "https":
                msg = "Deployment mode requires an HTTPS OAuth2 issuer"
                raise ValueError(msg)
            self._reject_local_url(
                name="oauth2.jwt_issuer",
                value=self.oauth2.jwt_issuer,
            )
        frontend_base_url = str(self.auth.email.frontend_base_url)
        if urlsplit(frontend_base_url).scheme != "https":
            msg = "Deployment mode requires an HTTPS email frontend URL"
            raise ValueError(msg)
        self._validate_deployment_origin(
            name="auth.email.frontend_base_url",
            value=frontend_base_url,
        )
        if self.default_redirect_url is not None:
            default_redirect_url = str(self.default_redirect_url)
            if urlsplit(default_redirect_url).scheme != "https":
                msg = "Deployment mode requires an HTTPS default redirect URL"
                raise ValueError(msg)
            self._reject_local_url(
                name="default_redirect_url",
                value=default_redirect_url,
            )
        if self.ui.external_login_url is not None:
            external_login_url = str(self.ui.external_login_url)
            if urlsplit(external_login_url).scheme != "https":
                msg = "Deployment mode requires an HTTPS external login URL"
                raise ValueError(msg)
            self._reject_local_url(
                name="ui.external_login_url",
                value=external_login_url,
            )

    def _validate_deployment_topology(self) -> None:
        """Validate unambiguous deployment topology invariants."""
        self._validate_deployment_cors()
        self._validate_deployment_session_topology()
        self._validate_deployment_public_urls()

    def _validate_deployment_settings(self) -> None:
        """Reject local-only defaults from an explicitly deployed server."""
        insecure_values: dict[str, tuple[str | None, str | None]] = {
            "auth.tokens.derivation_secret": (
                self.auth.tokens.derivation_secret.get_secret_value(),
                DEFAULT_AUTH_TOKEN_DERIVATION_SECRET,
            ),
        }
        if self.session.enabled:
            insecure_values["session.id_hash_secret"] = (
                self.session.id_hash_secret.get_secret_value(),
                DEFAULT_SESSION_ID_HASH_SECRET,
            )
        if self.oauth2.protocol_enabled:
            insecure_values.update(
                {
                    "oauth2.authorization_code_hash_secret": (
                        self.oauth2.authorization_code_hash_secret.get_secret_value(),
                        DEFAULT_AUTHORIZATION_CODE_HASH_SECRET,
                    ),
                    "oauth2.token_hash_secret": (
                        self.oauth2.token_hash_secret.get_secret_value(),
                        DEFAULT_TOKEN_HASH_SECRET,
                    ),
                    "oauth2.prv_key_b64": (
                        self.oauth2.prv_key_b64,
                        DEV_OAUTH2_PRIVATE_KEY_B64,
                    ),
                    "oauth2.pub_key_b64": (
                        self.oauth2.pub_key_b64,
                        DEV_OAUTH2_PUBLIC_KEY_B64,
                    ),
                    "oauth2.jwt_key_id": (
                        self.oauth2.jwt_key_id,
                        "local-dev-key",
                    ),
                }
            )
        insecure_names = [
            name
            for name, (actual, local_default) in insecure_values.items()
            if actual in {local_default, EXAMPLE_SECRET_PLACEHOLDER}
        ]
        if insecure_names:
            names = ", ".join(insecure_names)
            msg = f"Deployment mode rejects development secrets: {names}"
            raise ValueError(msg)
        if not self.app.trusted_hosts:
            msg = "Deployment mode requires explicit trusted_hosts"
            raise ValueError(msg)
        self._validate_deployment_network_inputs()
        self._validate_deployment_topology()
        if not self.mail.enabled:
            msg = "Deployment mode requires mail delivery for identity workflows"
            raise ValueError(msg)


def load_settings() -> Settings:
    """Load application settings from TOML and environment overrides."""
    return Settings()
