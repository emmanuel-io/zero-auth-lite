"""Tests for server configuration loading and validation."""

import base64
import tomllib
from pathlib import Path

import pytest
from app.browser_sessions.settings import BrowserSessionSettings
from app.oauth2.grants.types import OAuth2GrantType
from app.oauth2.settings import (
    DEFAULT_AUTHORIZATION_CODE_HASH_SECRET,
    DEFAULT_TOKEN_HASH_SECRET,
    OAuth2Settings,
)
from app.settings.api import APISettings
from app.settings.cors import CorsSettings
from app.settings.identity_workflow import IdentityWorkflowSettings
from app.settings.root import DatabaseSettings, Settings
from app.settings.ui import (
    IdentityWorkflowUIMode,
    ManagementAuthenticationMode,
    OAuth2InteractionUIMode,
    UISettings,
    UIURLs,
)
from app.workflow_tokens.settings import (
    DEFAULT_WORKFLOW_TOKEN_DERIVATION_SECRET,
    PreviousDerivationSecretSettings,
    WorkflowTokenSettings,
)
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from pydantic import SecretStr, ValidationError
from pydantic_settings import SettingsError


pytestmark = pytest.mark.unit
PROJECT_ROOT = Path(__file__).parents[3]
EXPECTED_SESSION_CLEANUP_BATCH_SIZE = 100


def builtin_absolute_urls(origin: str) -> dict[str, str]:
    """Return absolute destinations served by the built-in authentication UI."""
    return {
        "verification": f"{origin}/verify-email",
        "password_reset": f"{origin}/reset-password",
        "invitation": f"{origin}/accept-invite",
        "device_interaction": f"{origin}/oauth2/device/verify",
    }


def deployment_settings_kwargs() -> dict[str, object]:
    """Return a valid deployment baseline for focused negative tests."""
    return {
        "app": {"environment": "deployment", "trusted_hosts": ["auth.example"]},
        "cors": {"allowed_origins": ["https://app.example"]},
        "browser_session": {
            "cookie_domain": "auth.example",
            "hash_secret": "session-secret-at-least-32-characters",
            "csrf": {
                "cookie_domain": "auth.example",
                "public_origin": "https://auth.example",
                "trusted_origins": ["https://app.example"],
            },
        },
        "oauth2": OAuth2Settings.disabled(),
        "identity_workflow": {
            "workflow_tokens": {
                "derivation_secret": "workflow-secret-at-least-32-characters"
            },
        },
        "ui": {
            "urls": {
                "verification": "https://auth.example/verify-email",
                "password_reset": "https://auth.example/reset-password",
                "invitation": "https://auth.example/accept-invite",
                "device_interaction": ("https://auth.example/oauth2/device/verify"),
            }
        },
        "mail": {
            "default_from_email": "no-reply@auth.example",
            "smtp_starttls": True,
        },
    }


def deployment_oauth2_settings(*, issuer: str) -> OAuth2Settings:
    """Return non-development signing material for deployment validation."""
    private_key = ed25519.Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
    private_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_bytes = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return OAuth2Settings(
        signing_private_key_b64=base64.b64encode(private_bytes).decode(),
        signing_public_key_b64=base64.b64encode(public_bytes).decode(),
        authorization_code_hash_secret="code-secret-at-least-32-characters",  # noqa: S106
        token_hash_secret="token-secret-at-least-32-characters",  # noqa: S106
        signing_key_id="deployment-key",
        issuer=issuer,
    )


def test_oauth2_private_signing_key_is_redacted() -> None:
    """Keep private signing material out of settings representations and JSON."""
    private_key = "private-key-material"
    settings = OAuth2Settings(signing_private_key_b64=private_key)

    assert private_key not in repr(settings)
    assert private_key not in settings.model_dump_json()
    assert settings.signing_private_key_b64 is not None
    assert settings.signing_private_key_b64.get_secret_value() == private_key


def merge_setting_updates(
    target: dict[str, object], updates: dict[str, object]
) -> None:
    """Recursively apply focused updates to a complete settings mapping."""
    for name, value in updates.items():
        current = target.get(name)
        if isinstance(current, dict) and isinstance(value, dict):
            merge_setting_updates(current, value)
        else:
            target[name] = value


def test_cors_origins_require_an_explicit_collection() -> None:
    """Reject a string that Starlette would interpret using substring matching."""
    with pytest.raises(ValidationError, match="allowed_origins"):
        CorsSettings(allowed_origins="https://example.com")

    settings = CorsSettings(allowed_origins=("https://example.com",))

    assert settings.allowed_origins == ("https://example.com",)


def test_deployment_allows_an_empty_cors_origin_collection() -> None:
    """Allow same-origin deployments to leave CORS middleware unmounted."""
    values = deployment_settings_kwargs()
    values["cors"] = {"allowed_origins": []}

    settings = Settings.model_validate(values)

    assert settings.cors.allowed_origins == ()


@pytest.mark.negative
@pytest.mark.parametrize(
    "url",
    [
        "https://user@app.example",
        "https://user:password@app.example",
        "https://app.example?source=email",
        "https://app.example#workflow",
    ],
)
def test_ui_url_rejects_ambiguous_components(url: str) -> None:
    """Reject components that would corrupt server-controlled query values."""
    with pytest.raises(ValidationError, match="UI URLs"):
        UIURLs(verification=url)


@pytest.mark.negative
@pytest.mark.parametrize(
    "url",
    [
        "/log\x00in",
        "/log\nin",
        "/log\x7fin",
        "https://app.example/log\x00in",
        "https://app.example/log\nin",
        "https://app.example/log\x7fin",
    ],
)
def test_ui_url_rejects_ascii_control_characters(url: str) -> None:
    """Reject every ASCII control character from navigation destinations."""
    with pytest.raises(ValidationError, match="UI URLs"):
        UIURLs(login=url)


def test_ui_urls_default_to_builtin_destinations() -> None:
    """Expose one complete set of destinations without extra configuration."""
    urls = UIURLs()

    assert urls.login == "/login"
    assert urls.logout == "/logout"
    assert urls.verification.endswith("/verify-email")
    assert urls.password_reset.endswith("/reset-password")
    assert urls.invitation.endswith("/accept-invite")
    assert urls.authorization_interaction == "/login"
    assert urls.authorization_consent == "/consent"
    assert urls.device_interaction.endswith("/oauth2/device/verify")


@pytest.mark.negative
@pytest.mark.parametrize(
    ("name", "url", "path"),
    [
        ("login", "/sign-in", "/login"),
        ("logout", "/sign-out", "/logout"),
        ("verification", "https://auth.example/verify", "/verify-email"),
        ("password_reset", "https://auth.example/reset", "/reset-password"),
        ("invitation", "https://auth.example/invite", "/accept-invite"),
        ("authorization_interaction", "/authorize", "/login"),
        ("authorization_consent", "/authorize/consent", "/consent"),
        (
            "device_interaction",
            "https://auth.example/device",
            "/oauth2/device/verify",
        ),
    ],
)
def test_builtin_ui_requires_its_canonical_url(name: str, url: str, path: str) -> None:
    """Reject configured destinations that do not serve the mounted page."""
    with pytest.raises(ValidationError, match=rf"{name}.*{path}"):
        Settings(ui={"urls": {name: url}})


@pytest.mark.negative
@pytest.mark.parametrize(
    ("name", "path"),
    [
        ("verification", "/verify-email"),
        ("password_reset", "/reset-password"),
        ("invitation", "/accept-invite"),
        ("device_interaction", "/oauth2/device/verify"),
    ],
)
def test_builtin_absolute_ui_urls_require_public_auth_origin(
    name: str, path: str
) -> None:
    """Reject a built-in token destination hosted on another origin."""
    urls = builtin_absolute_urls("https://auth.example")
    urls[name] = f"https://attacker.example{path}"

    with pytest.raises(ValidationError, match=rf"{name}.*auth\.example.*{path}"):
        Settings(
            browser_session={"csrf": {"public_origin": "https://auth.example"}},
            ui={"urls": urls},
        )


def test_builtin_absolute_ui_urls_accept_public_auth_origin() -> None:
    """Accept every built-in token destination on the public auth origin."""
    origin = "https://auth.example"
    settings = Settings(
        browser_session={"csrf": {"public_origin": origin}},
        ui={
            "urls": {
                **builtin_absolute_urls(origin),
            }
        },
    )

    assert settings.browser_session.csrf.public_origin == origin


def test_settings_loads_the_default_toml_file(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """Load the optional conventional TOML file from the working directory."""
    monkeypatch.chdir(tmp_path)
    (tmp_path / "zero-auth-lite.toml").write_text(
        'db_path = "tmp/from-toml.db"\n\n[app]\nlog_level = "DEBUG"\n'
    )

    settings = Settings()

    assert settings.db_path == Path("tmp/from-toml.db")
    assert settings.app.log_level == "DEBUG"


def test_management_ui_toggles_load_from_environment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Expose independent organization and operator browser-route toggles."""
    monkeypatch.setenv("ZA_UI__ORGANIZATION_ADMIN_ENABLED", "false")
    monkeypatch.setenv("ZA_UI__OPERATOR_ENABLED", "false")

    settings = Settings()

    assert settings.ui.organization_admin_enabled is False
    assert settings.ui.operator_enabled is False


def test_management_ui_toggles_default_to_enabled() -> None:
    """Enable both management browser surfaces by default."""
    settings = UISettings()

    assert settings.organization_admin_enabled is True
    assert settings.operator_enabled is True


def test_management_ui_toggles_load_from_toml(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """Read both management presentation flags from the UI TOML table."""
    monkeypatch.chdir(tmp_path)
    (tmp_path / "zero-auth-lite.toml").write_text(
        "[ui]\norganization_admin_enabled = false\noperator_enabled = false\n"
    )

    settings = Settings()

    assert settings.ui.organization_admin_enabled is False
    assert settings.ui.operator_enabled is False


def test_settings_loads_an_explicit_toml_file(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """Select a TOML file through the dedicated loader environment variable."""
    config_path = tmp_path / "selected.toml"
    config_path.write_text(
        """
[browser_session]
cookie_name = "toml-session"

[identity_workflow.workflow_tokens]
previous_derivation_secrets = [
  { key_id = "retained", secret = "retained-secret-at-least-32-characters" },
]
"""
    )
    monkeypatch.setenv("ZA_CONFIG_FILE", str(config_path))

    settings = Settings()

    assert settings.browser_session.cookie_name == "toml-session"
    retained = settings.identity_workflow.workflow_tokens.derivation_secret_for(
        "retained"
    )
    assert retained is not None
    assert retained.get_secret_value() == "retained-secret-at-least-32-characters"


@pytest.mark.negative
def test_explicit_toml_file_must_exist(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """Fail startup when an explicitly selected TOML file is absent."""
    missing_path = tmp_path / "missing.toml"
    monkeypatch.setenv("ZA_CONFIG_FILE", str(missing_path))

    with pytest.raises(SettingsError, match=r"ZA_CONFIG_FILE.*missing\.toml"):
        Settings()


@pytest.mark.negative
def test_toml_file_must_be_valid(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """Fail startup when the selected file is not valid TOML."""
    config_path = tmp_path / "invalid.toml"
    config_path.write_text("[app\n")
    monkeypatch.setenv("ZA_CONFIG_FILE", str(config_path))

    with pytest.raises(tomllib.TOMLDecodeError):
        Settings()


@pytest.mark.negative
def test_toml_file_rejects_unknown_settings(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """Keep misspelled or unsupported TOML settings from being ignored."""
    config_path = tmp_path / "unknown.toml"
    config_path.write_text("unknown_setting = true\n")
    monkeypatch.setenv("ZA_CONFIG_FILE", str(config_path))

    with pytest.raises(ValidationError, match="unknown_setting"):
        Settings()


def test_python_and_environment_values_override_toml(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """Apply Python, environment, TOML, and default precedence in that order."""
    config_path = tmp_path / "precedence.toml"
    config_path.write_text(
        """
[oauth2]
access_token_audience = "toml-audience"
signing_key_id = "toml-key"

[browser_session]
cookie_name = "toml-session"
"""
    )
    monkeypatch.setenv("ZA_CONFIG_FILE", str(config_path))
    monkeypatch.setenv("ZA_OAUTH2__ACCESS_TOKEN_AUDIENCE", "environment-audience")
    monkeypatch.setenv("ZA_BROWSER_SESSION__COOKIE_NAME", "environment-session")

    settings = Settings(oauth2={"access_token_audience": "python-audience"})

    assert settings.oauth2.access_token_audience == "python-audience"  # noqa: S105
    assert settings.oauth2.signing_key_id == "toml-key"
    assert settings.browser_session.cookie_name == "environment-session"
    assert settings.browser_session.ttl_seconds == BrowserSessionSettings().ttl_seconds


def test_settings_reads_database_environment_variables(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Load the database path and SQL logging flag from root settings."""
    monkeypatch.setenv("ZA_DB_PATH", "tmp/zero-auth-lite.db")
    monkeypatch.setenv("ZA_DB_ECHO", "true")
    settings = Settings()

    assert settings.db_path == Path("tmp/zero-auth-lite.db")
    assert settings.db_echo is True


def test_database_settings_ignore_unrelated_server_configuration(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """Keep schema management independent from application startup policy."""
    config_path = tmp_path / "migration.toml"
    database_path = tmp_path / "from-toml.db"
    config_path.write_text(
        f"""
db_path = "{database_path}"

[app]
environment = "deployment"

[oauth2]
authorization_code_enabled = true
"""
    )
    monkeypatch.setenv("ZA_CONFIG_FILE", str(config_path))
    monkeypatch.setenv("ZA_DB_ECHO", "true")

    settings = DatabaseSettings()

    assert settings.db_path == database_path
    assert settings.db_echo is True


def test_settings_reads_session_hash_secret_environment_variable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Load the root secret used for domain-separated session hashes."""
    secret = "environment-session-hash-secret-value"  # noqa: S105
    monkeypatch.setenv("ZA_BROWSER_SESSION__HASH_SECRET", secret)

    settings = Settings()

    assert settings.browser_session.hash_secret.get_secret_value() == secret


@pytest.mark.negative
@pytest.mark.parametrize(
    "name",
    [
        "ZA_AUTH__REGISTRATION_ENABLED",
        "ZA_SESSION__ENABLED",
        "ZA_API__BROWSER_FLOWS_ENABLED",
        "ZA_API__BROWSER_TRANSPORT_ENABLED",
        "ZA_UI__IDENTITY_WORKFLOW",
    ],
)
def test_settings_rejects_unsupported_environment_names(
    name: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Reject old root names instead of silently ignoring configuration."""
    monkeypatch.setenv(name, "false")

    with pytest.raises(SettingsError, match=name):
        Settings()


@pytest.mark.negative
def test_session_settings_rejects_retired_id_hash_secret_name() -> None:
    """Keep the configuration rename explicit instead of accepting an alias."""
    with pytest.raises(ValidationError, match="id_hash_secret"):
        BrowserSessionSettings.model_validate({"id_hash_secret": "s" * 32})


def test_settings_reads_runtime_directory(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """Load the shared process runtime directory."""
    monkeypatch.setenv("ZA_RUNTIME_DIR", str(tmp_path))

    settings = Settings()

    assert settings.runtime_dir == tmp_path


@pytest.mark.negative
def test_settings_rejects_retired_snowflake_node_id(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Reject the removed Snowflake configuration explicitly."""
    monkeypatch.setenv("ZA_SNOWFLAKE_NODE_ID", "1024")

    with pytest.raises(SettingsError, match="ZA_SNOWFLAKE_NODE_ID"):
        Settings()


def test_nested_environment_override_preserves_section_defaults(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Change one nested value without rebuilding the section from other defaults."""
    monkeypatch.setenv("ZA_OAUTH2__ACCESS_TOKEN_AUDIENCE", "custom-audience")
    monkeypatch.setenv("ZA_BROWSER_SESSION__COOKIE_NAME", "custom-session")
    settings = Settings()

    assert settings.oauth2.access_token_audience == "custom-audience"  # noqa: S105
    assert settings.oauth2.enabled_grants() == OAuth2Settings().enabled_grants()
    assert settings.oauth2.oidc_enabled is True
    assert settings.oauth2.jwks_enabled is True
    assert settings.browser_session.cookie_name == "custom-session"
    assert settings.browser_session.csrf.public_origin is not None


@pytest.mark.negative
@pytest.mark.parametrize(
    "issuer",
    [
        "https://user@example.com",
        "https://user:password@example.com",
    ],
)
def test_oauth2_issuer_rejects_user_information(issuer: str) -> None:
    """Prevent credentials from becoming part of the public issuer identifier."""
    with pytest.raises(ValidationError, match="must not contain user information"):
        OAuth2Settings(issuer=issuer)


@pytest.mark.negative
@pytest.mark.parametrize(
    "issuer",
    [
        "https://:443",
        "https://issuer.example:not-a-port",
        "https://bad host",
    ],
)
def test_oauth2_issuer_rejects_invalid_hostname_or_port(issuer: str) -> None:
    """Require a syntactically valid host authority for the issuer."""
    with pytest.raises(ValidationError, match=r"absolute HTTP.*URL"):
        OAuth2Settings(issuer=issuer)


def test_workflow_token_derivation_keyring_loads_from_environment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Load the active derivation key and retained rotation keys explicitly."""
    monkeypatch.setenv(
        "ZA_IDENTITY_WORKFLOW__WORKFLOW_TOKENS__DERIVATION_KEY_ID", "2026-09"
    )
    monkeypatch.setenv(
        "ZA_IDENTITY_WORKFLOW__WORKFLOW_TOKENS__PREVIOUS_DERIVATION_SECRETS",
        '[{"key_id":"2026-08","secret":"retained-secret-at-least-32-characters"}]',
    )

    settings = Settings()

    assert settings.identity_workflow.workflow_tokens.derivation_key_id == "2026-09"
    retained = settings.identity_workflow.workflow_tokens.derivation_secret_for(
        "2026-08"
    )
    assert retained is not None
    assert retained.get_secret_value() == "retained-secret-at-least-32-characters"


def test_public_registration_policy_loads_from_environment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Allow deployments to close public signup explicitly."""
    monkeypatch.setenv("ZA_IDENTITY_WORKFLOW__REGISTRATION_ENABLED", "false")

    settings = Settings()

    assert settings.identity_workflow.registration_enabled is False


@pytest.mark.negative
def test_deployment_mode_rejects_local_security_defaults() -> None:
    """Prevent an explicitly deployed server from reusing public local secrets."""
    with pytest.raises(ValidationError, match="development secrets"):
        Settings(app={"environment": "deployment"})


def test_deployment_mode_accepts_explicit_non_local_topology() -> None:
    """Accept a complete deployment snapshot with non-local public hosts."""
    settings = Settings.model_validate(deployment_settings_kwargs())

    assert settings.app.environment == "deployment"


@pytest.mark.negative
def test_deployment_mode_rejects_wildcard_trusted_host() -> None:
    """Prevent deployment mode from disabling host-header validation."""
    values = deployment_settings_kwargs()
    values["app"] = {"environment": "deployment", "trusted_hosts": ["*"]}

    with pytest.raises(ValidationError, match="restrictive trusted_hosts"):
        Settings.model_validate(values)


@pytest.mark.negative
def test_settings_reject_invalid_trusted_proxy_network() -> None:
    """Fail closed on malformed proxy networks in every environment."""
    with pytest.raises(ValidationError, match=r"app\.trusted_proxy_ips"):
        Settings(app={"trusted_proxy_ips": ["not-a-network"]})


@pytest.mark.negative
def test_deployment_mode_rejects_committed_secret_placeholder() -> None:
    """Reject the syntactically valid placeholder distributed in env examples."""
    values = deployment_settings_kwargs()
    merge_setting_updates(
        values,
        {
            "browser_session": {
                "hash_secret": "replace-with-at-least-32-random-characters"
            }
        },
    )

    with pytest.raises(ValidationError, match=r"session\.hash_secret"):
        Settings.model_validate(values)


@pytest.mark.negative
def test_device_flow_requires_an_interaction_ui() -> None:
    """Reject a device flow that would advertise an unavailable verification URI."""
    with pytest.raises(ValidationError, match=r"device code.*built-in or external UI"):
        Settings(ui={"oauth2_interaction": "disabled"})


def test_device_flow_accepts_external_interaction_ui() -> None:
    """Allow Device Code when a JSON-backed external UI is configured."""
    settings = Settings(
        ui=UISettings(
            identity_workflow_mode=IdentityWorkflowUIMode.EXTERNAL,
            oauth2_interaction=OAuth2InteractionUIMode.EXTERNAL,
            urls={
                "verification": "https://frontend.example/verify",
                "password_reset": "https://frontend.example/reset",
                "invitation": "https://frontend.example/invite",
                "authorization_interaction": (
                    "https://frontend.example/oauth2/authorization"
                ),
                "device_interaction": "https://frontend.example/oauth2/device",
            },
        ),
    )

    assert settings.ui.oauth2_interaction_is_external is True


@pytest.mark.negative
def test_external_management_requires_interactive_api_routes() -> None:
    """Reject external management login without its session JSON adapter."""
    with pytest.raises(ValidationError, match=r"interactive authentication API routes"):
        Settings(
            api=APISettings(interactive_auth_routes_enabled=False),
            ui=UISettings(
                management_authentication=ManagementAuthenticationMode.EXTERNAL,
                urls={
                    "login": "https://frontend.example/login",
                    "logout": "https://frontend.example/logout",
                },
            ),
        )


def test_headless_identity_workflows_accept_external_urls() -> None:
    """Allow JSON workflow clients to own every notification destination."""
    settings = Settings(
        ui=UISettings(
            identity_workflow_mode=IdentityWorkflowUIMode.DISABLED,
            urls={
                "verification": "https://frontend.example/verify-email",
                "password_reset": "https://frontend.example/reset-password",
                "invitation": "https://frontend.example/accept-invite",
            },
        )
    )

    assert settings.ui.identity_workflow_is_disabled is True
    assert settings.api.interactive_auth_routes_enabled is True


@pytest.mark.negative
@pytest.mark.parametrize("url_name", ["verification", "password_reset", "invitation"])
def test_headless_identity_workflows_require_absolute_urls(url_name: str) -> None:
    """Reject a notification destination that no mounted page can consume."""
    with pytest.raises(
        ValidationError,
        match=rf"absolute HTTP\(S\) URL.*ui\.urls\.{url_name}",
    ):
        Settings(
            ui=UISettings(
                identity_workflow_mode=IdentityWorkflowUIMode.DISABLED,
                urls={
                    "verification": "https://frontend.example/verify-email",
                    "password_reset": "https://frontend.example/reset-password",
                    "invitation": "https://frontend.example/accept-invite",
                    url_name: f"/{url_name}",
                },
            )
        )


@pytest.mark.negative
def test_deployment_rejects_local_headless_workflow_urls() -> None:
    """Apply deployment URL policy when only the JSON workflow transport remains."""
    values = deployment_settings_kwargs()
    merge_setting_updates(
        values,
        {
            "ui": {
                "identity_workflow_mode": "disabled",
                "urls": {"verification": "https://frontend.localhost/verify-email"},
            }
        },
    )

    with pytest.raises(ValidationError, match=r"ui\.urls\.verification"):
        Settings.model_validate(values)


@pytest.mark.negative
@pytest.mark.parametrize(
    ("api", "missing"),
    [
        (
            APISettings(interactive_auth_routes_enabled=False),
            "interactive authentication API routes",
        ),
        (APISettings(), "ui.urls.authorization_interaction"),
    ],
)
def test_external_oauth2_interaction_requires_api_and_url(
    api: APISettings, missing: str
) -> None:
    """Reject incomplete external OAuth2 interaction configurations."""
    with pytest.raises(ValidationError, match=missing):
        Settings(
            api=api,
            ui=UISettings(
                oauth2_interaction=OAuth2InteractionUIMode.EXTERNAL,
            ),
        )


def test_noninteractive_oauth2_ignores_external_interactive_routes() -> None:
    """Allow an inert external interaction mode without browser JSON transport."""
    settings = Settings(
        api=APISettings(interactive_auth_routes_enabled=False),
        oauth2={
            "authorization_code_enabled": False,
            "refresh_token_enabled": False,
            "device_code_enabled": False,
            "oidc_enabled": False,
            "client_credentials_enabled": True,
        },
        ui=UISettings(oauth2_interaction=OAuth2InteractionUIMode.EXTERNAL),
    )

    assert settings.ui.oauth2_interaction_is_external is True
    assert settings.api.interactive_auth_routes_enabled is False


@pytest.mark.negative
def test_deployment_mode_requires_mail_delivery() -> None:
    """Require mail delivery while authentication workflows are exposed."""
    mail_values = deployment_settings_kwargs()
    mail_values["mail"] = {"enabled": False}
    with pytest.raises(ValidationError, match="mail delivery"):
        Settings.model_validate(mail_values)


@pytest.mark.negative
def test_deployment_mode_requires_smtp_tls() -> None:
    """Protect workflow links in transit to the deployment SMTP relay."""
    values = deployment_settings_kwargs()
    values["mail"] = {"enabled": True}

    with pytest.raises(ValidationError, match="SMTP SSL or STARTTLS"):
        Settings.model_validate(values)


@pytest.mark.negative
def test_deployment_mode_requires_explicit_mail_sender() -> None:
    """Reject the reserved local-example sender in deployment mode."""
    values = deployment_settings_kwargs()
    values["mail"] = {"smtp_starttls": True}

    with pytest.raises(ValidationError, match="explicit mail sender"):
        Settings.model_validate(values)


@pytest.mark.negative
def test_deployment_requires_mail_for_session_identity_workflows() -> None:
    """Require mail while sessions can reach account-management workflows."""
    values = deployment_settings_kwargs()
    merge_setting_updates(
        values,
        {
            "api": {"interactive_auth_routes_enabled": False},
            "identity_workflow": {"registration_enabled": False},
            "mail": {"enabled": False},
            "ui": {"identity_workflow_mode": "builtin"},
        },
    )

    with pytest.raises(ValidationError, match="mail delivery"):
        Settings.model_validate(values)


@pytest.mark.negative
def test_deployment_requires_workflow_secret_for_session_identity_workflows() -> None:
    """Reject the development workflow secret while sessions remain enabled."""
    values = deployment_settings_kwargs()
    merge_setting_updates(
        values,
        {
            "api": {"interactive_auth_routes_enabled": False},
            "identity_workflow": {
                "registration_enabled": False,
                "workflow_tokens": {
                    "derivation_secret": DEFAULT_WORKFLOW_TOKEN_DERIVATION_SECRET,
                },
            },
            "ui": {"identity_workflow_mode": "builtin"},
        },
    )

    with pytest.raises(
        ValidationError,
        match=r"identity_workflow\.workflow_tokens\.derivation_secret",
    ):
        Settings.model_validate(values)


@pytest.mark.negative
def test_auth_settings_rejects_unknown_tokens_key() -> None:
    """Keep workflow_tokens as the only supported token-settings key."""
    with pytest.raises(ValidationError, match="tokens"):
        IdentityWorkflowSettings.model_validate(
            {"tokens": {"derivation_key_id": "unknown"}}
        )


def test_machine_deployment_ignores_disabled_workflow_settings() -> None:
    """Require deployment secrets only for capabilities that remain enabled."""
    oauth2 = deployment_oauth2_settings(issuer="https://auth.example").model_copy(
        update={
            "authorization_code_enabled": False,
            "refresh_token_enabled": False,
            "device_code_enabled": False,
            "oidc_enabled": False,
            "authorization_code_hash_secret": SecretStr(
                DEFAULT_AUTHORIZATION_CODE_HASH_SECRET
            ),
        }
    )

    settings = Settings(
        app={"environment": "deployment", "trusted_hosts": ["auth.example"]},
        api={"interactive_auth_routes_enabled": False},
        cors={"allowed_origins": []},
        browser_session={"enabled": False},
        oauth2=oauth2,
        identity_workflow={"registration_enabled": False},
        mail={"enabled": False},
        ui={
            "identity_workflow_mode": "disabled",
            "oauth2_interaction": "disabled",
            "organization_admin_enabled": False,
            "operator_enabled": False,
        },
    )

    assert settings.oauth2.enabled_grants() == {OAuth2GrantType.CLIENT_CREDENTIALS}
    assert settings.ui.urls.verification.endswith("/verify-email")
    assert (
        settings.identity_workflow.workflow_tokens.derivation_secret.get_secret_value()
        == DEFAULT_WORKFLOW_TOKEN_DERIVATION_SECRET
    )


def test_jwks_only_deployment_ignores_grant_secrets() -> None:
    """Publish a verification key without requiring unused grant secrets."""
    oauth2 = deployment_oauth2_settings(issuer="https://auth.example").model_copy(
        update={
            "authorization_code_enabled": False,
            "refresh_token_enabled": False,
            "client_credentials_enabled": False,
            "device_code_enabled": False,
            "oidc_enabled": False,
            "signing_private_key_b64": None,
            "authorization_code_hash_secret": SecretStr(
                DEFAULT_AUTHORIZATION_CODE_HASH_SECRET
            ),
            "token_hash_secret": SecretStr(DEFAULT_TOKEN_HASH_SECRET),
        }
    )

    settings = Settings(
        app={"environment": "deployment", "trusted_hosts": ["auth.example"]},
        api={"interactive_auth_routes_enabled": False},
        cors={"allowed_origins": []},
        browser_session={
            "cookie_domain": "auth.example",
            "hash_secret": "session-secret-at-least-32-characters",
            "csrf": {
                "cookie_domain": "auth.example",
                "public_origin": "https://auth.example",
                "trusted_origins": [],
            },
        },
        oauth2=oauth2,
        identity_workflow={
            "registration_enabled": False,
            "workflow_tokens": {
                "derivation_secret": "workflow-secret-at-least-32-characters",
            },
        },
        mail={
            "default_from_email": "no-reply@auth.example",
            "smtp_starttls": True,
        },
        ui={
            "identity_workflow_mode": "builtin",
            "oauth2_interaction": "disabled",
            "organization_admin_enabled": False,
            "operator_enabled": False,
            "urls": {
                "verification": "https://auth.example/verify-email",
                "password_reset": "https://auth.example/reset-password",
                "invitation": "https://auth.example/accept-invite",
            },
        },
    )

    assert settings.oauth2.has_enabled_grants is False
    assert settings.oauth2.jwks_enabled is True


@pytest.mark.negative
def test_user_authentication_requires_an_identity_workflow_transport() -> None:
    """Reject user credentials when their identity links cannot be consumed."""
    with pytest.raises(ValidationError, match="User identity workflows require"):
        Settings(
            api=APISettings(interactive_auth_routes_enabled=False),
            identity_workflow=IdentityWorkflowSettings(registration_enabled=False),
            ui=UISettings(identity_workflow_mode=IdentityWorkflowUIMode.DISABLED),
        )


@pytest.mark.negative
def test_server_requires_an_authentication_mechanism() -> None:
    """Reject a canonical server with neither sessions nor OAuth2."""
    with pytest.raises(ValidationError, match="authentication mechanism"):
        Settings(
            browser_session=BrowserSessionSettings(enabled=False),
            identity_workflow=IdentityWorkflowSettings(registration_enabled=False),
            oauth2=OAuth2Settings.disabled(),
        )


@pytest.mark.negative
def test_deployment_mode_requires_secure_csrf_cookie() -> None:
    """Reject a CSRF cookie that can cross a plaintext transport."""
    values = deployment_settings_kwargs()
    merge_setting_updates(
        values, {"browser_session": {"csrf": {"cookie_secure": False}}}
    )

    with pytest.raises(ValidationError, match="secure CSRF cookies"):
        Settings.model_validate(values)


@pytest.mark.negative
def test_deployment_mode_requires_https_public_urls() -> None:
    """Require TLS for the OAuth2 issuer and workflow frontend URL."""
    issuer_values = deployment_settings_kwargs()
    issuer_values["oauth2"] = deployment_oauth2_settings(issuer="http://auth.example")
    with pytest.raises(ValidationError, match="HTTPS OAuth2 issuer"):
        Settings.model_validate(issuer_values)

    frontend_values = deployment_settings_kwargs()
    merge_setting_updates(
        frontend_values,
        {
            "ui": {
                "identity_workflow_mode": "external",
                "urls": {"verification": "http://app.example/verify-email"},
            }
        },
    )
    with pytest.raises(ValidationError, match="verification UI URL"):
        Settings.model_validate(frontend_values)

    login_values = deployment_settings_kwargs()
    merge_setting_updates(
        login_values,
        {
            "ui": {
                "management_authentication": "external",
                "urls": {
                    "login": "http://frontend.example/login",
                    "logout": "https://frontend.test/logout",
                },
            }
        },
    )
    merge_setting_updates(login_values, {"ui": {"identity_workflow_mode": "external"}})
    with pytest.raises(ValidationError, match="login UI URL"):
        Settings.model_validate(login_values)

    logout_values = deployment_settings_kwargs()
    merge_setting_updates(
        logout_values,
        {
            "ui": {
                "management_authentication": "external",
                "urls": {
                    "login": "https://frontend.example/login",
                    "logout": "http://frontend.example/logout",
                },
            }
        },
    )
    merge_setting_updates(logout_values, {"ui": {"identity_workflow_mode": "external"}})
    with pytest.raises(ValidationError, match="logout UI URL"):
        Settings.model_validate(logout_values)


@pytest.mark.negative
@pytest.mark.parametrize(
    ("updates", "setting_name"),
    [
        (
            {"cors": {"allowed_origins": ["http://localhost:3000"]}},
            "cors.allowed_origins",
        ),
        (
            {"browser_session": {"cookie_domain": "zero-auth-lite.localhost"}},
            "browser_session.cookie_domain",
        ),
        (
            {"browser_session": {"csrf": {"cookie_domain": ".localhost"}}},
            "browser_session.csrf.cookie_domain",
        ),
        (
            {"browser_session": {"csrf": {"public_origin": "https://auth.localhost"}}},
            "browser_session.csrf.public_origin",
        ),
        (
            {"browser_session": {"csrf": {"trusted_origins": ["https://127.0.0.1"]}}},
            "browser_session.csrf.trusted_origins",
        ),
        (
            {"ui": {"urls": {"verification": "https://[::1]/verify-email"}}},
            "ui.urls.verification",
        ),
        (
            {"ui": {"urls": {"login": "https://frontend.localhost/login"}}},
            "ui.urls.login",
        ),
        (
            {"ui": {"urls": {"logout": "https://frontend.localhost/logout"}}},
            "ui.urls.logout",
        ),
    ],
)
def test_deployment_mode_rejects_local_only_topology(
    updates: dict[str, object], setting_name: str
) -> None:
    """Reject browser and workflow topology reserved for local examples."""
    values = deployment_settings_kwargs()
    merge_setting_updates(values, updates)

    with pytest.raises(ValidationError, match=setting_name):
        Settings.model_validate(values)


@pytest.mark.negative
@pytest.mark.parametrize(
    ("updates", "setting_name"),
    [
        (
            {"cors": {"allowed_origins": ["http://app.example"]}},
            "cors.allowed_origins",
        ),
        (
            {"browser_session": {"csrf": {"public_origin": "http://auth.example"}}},
            "browser_session.csrf.public_origin",
        ),
        (
            {"browser_session": {"csrf": {"trusted_origins": ["http://app.example"]}}},
            "browser_session.csrf.trusted_origins",
        ),
    ],
)
def test_deployment_mode_requires_https_origins(
    updates: dict[str, object], setting_name: str
) -> None:
    """Reject insecure browser origins in deployment mode."""
    values = deployment_settings_kwargs()
    merge_setting_updates(values, updates)

    with pytest.raises(ValidationError, match=setting_name):
        Settings.model_validate(values)


@pytest.mark.negative
def test_deployment_mode_rejects_local_oauth2_issuer() -> None:
    """Reject a loopback or localhost issuer even when it uses HTTPS."""
    values = deployment_settings_kwargs()
    values["oauth2"] = deployment_oauth2_settings(issuer="https://auth.localhost")

    with pytest.raises(ValidationError, match=r"oauth2\.issuer"):
        Settings.model_validate(values)


@pytest.mark.negative
@pytest.mark.parametrize(
    ("csrf", "setting_name"),
    [
        ({"public_origin": "not-an-origin"}, "public_origin"),
        ({"public_origin": "https://bad host"}, "public_origin"),
        ({"trusted_origins": ["https://app.example/path"]}, "trusted_origins"),
    ],
)
def test_deployment_mode_requires_absolute_csrf_origins(
    csrf: dict[str, object], setting_name: str
) -> None:
    """Reject malformed CSRF origins while allowing separate frontend hosts."""
    values = deployment_settings_kwargs()
    merge_setting_updates(values, {"browser_session": {"csrf": csrf}})

    with pytest.raises(ValidationError, match=setting_name):
        Settings.model_validate(values)


def test_deployment_topology_accepts_wildcard_host_and_separate_frontend() -> None:
    """Accept a trusted IdP subdomain without conflating it with the frontend."""
    values = deployment_settings_kwargs()
    values["app"] = {
        "environment": "deployment",
        "trusted_hosts": ["*.example"],
    }

    settings = Settings.model_validate(values)

    assert settings.browser_session.csrf.trusted_origins == ("https://app.example",)


def test_deployment_topology_accepts_host_only_cookies() -> None:
    """Allow the browser to bind both cookies to the public request host."""
    values = deployment_settings_kwargs()
    merge_setting_updates(
        values,
        {"browser_session": {"cookie_domain": "", "csrf": {"cookie_domain": ""}}},
    )

    settings = Settings.model_validate(values)

    assert settings.browser_session.cookie_domain == ""
    assert settings.browser_session.csrf.cookie_domain == ""


@pytest.mark.negative
@pytest.mark.parametrize(
    ("updates", "setting_name"),
    [
        (
            {"browser_session": {"csrf": {"public_origin": "https://other.example"}}},
            "browser_session.csrf.public_origin",
        ),
        (
            {"browser_session": {"cookie_domain": "sessions.example"}},
            "browser_session.cookie_domain",
        ),
        (
            {"browser_session": {"csrf": {"cookie_domain": "https://auth.example"}}},
            "browser_session.csrf.cookie_domain",
        ),
    ],
)
def test_deployment_topology_rejects_inconsistent_session_hosts(
    updates: dict[str, object], setting_name: str
) -> None:
    """Reject public and cookie hosts that do not describe the IdP boundary."""
    values = deployment_settings_kwargs()
    merge_setting_updates(values, updates)

    with pytest.raises(ValidationError, match=setting_name):
        Settings.model_validate(values)


@pytest.mark.negative
def test_deployment_topology_rejects_untrusted_oauth2_issuer() -> None:
    """Require the protocol issuer to be accepted by host middleware."""
    values = deployment_settings_kwargs()
    values["oauth2"] = deployment_oauth2_settings(issuer="https://issuer.example")

    with pytest.raises(ValidationError, match=r"oauth2\.issuer"):
        Settings.model_validate(values)


def test_http_origins_are_stored_in_canonical_form() -> None:
    """Normalize equivalent configured origins before exact comparisons."""
    settings = Settings(
        cors={"allowed_origins": ["HTTPS://APP.Example:443/"]},
        browser_session={
            "csrf": {
                "public_origin": "HTTPS://AUTH.Example:443/",
                "trusted_origins": ["https://APP.Example/"],
            }
        },
        ui={"urls": builtin_absolute_urls("https://auth.example")},
    )

    assert settings.cors.allowed_origins == ("https://app.example",)
    assert settings.browser_session.csrf.public_origin == "https://auth.example"
    assert settings.browser_session.csrf.trusted_origins == ("https://app.example",)


def test_oauth2_interaction_ui_loads_from_environment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Select the complete built-in presentation surface with one setting."""
    monkeypatch.setenv("ZA_UI__OAUTH2_INTERACTION", "disabled")
    monkeypatch.setenv("ZA_OAUTH2__DEVICE_CODE_ENABLED", "false")

    settings = Settings()

    assert settings.ui.oauth2_interaction.value == "disabled"
    assert settings.ui.oauth2_interaction_is_builtin is False


def test_authentication_ui_loads_from_environment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Select exactly one interactive authentication transport."""
    assert Settings().ui.management_authentication_is_builtin is True
    monkeypatch.setenv("ZA_UI__IDENTITY_WORKFLOW_MODE", "external")
    monkeypatch.setenv("ZA_UI__MANAGEMENT_AUTHENTICATION", "external")
    monkeypatch.setenv(
        "ZA_UI__URLS__LOGIN",
        "https://frontend.example/login",
    )
    monkeypatch.setenv(
        "ZA_UI__URLS__LOGOUT",
        "https://frontend.example/logout",
    )
    monkeypatch.setenv("ZA_UI__URLS__VERIFICATION", "https://frontend.example/verify")
    monkeypatch.setenv("ZA_UI__URLS__PASSWORD_RESET", "https://frontend.example/reset")
    monkeypatch.setenv("ZA_UI__URLS__INVITATION", "https://frontend.example/invite")

    settings = Settings()

    assert (
        settings.ui.management_authentication is ManagementAuthenticationMode.EXTERNAL
    )
    assert settings.ui.identity_workflow_mode is IdentityWorkflowUIMode.EXTERNAL
    assert settings.ui.urls.login == "https://frontend.example/login"
    assert settings.ui.urls.logout == "https://frontend.example/logout"


def test_interactive_api_routes_load_independently_from_environment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Configure the JSON workflow transport independently from presentation."""
    monkeypatch.setenv("ZA_API__INTERACTIVE_AUTH_ROUTES_ENABLED", "false")

    settings = Settings()

    assert settings.api.interactive_auth_routes_enabled is False


@pytest.mark.negative
def test_api_settings_rejects_retired_browser_transport_toml_field(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """Reject the retired TOML field instead of accepting an alias."""
    config_path = tmp_path / "retired-browser-transport.toml"
    config_path.write_text("[api]\nbrowser_transport_enabled = false\n")
    monkeypatch.setenv("ZA_CONFIG_FILE", str(config_path))

    with pytest.raises(ValidationError, match="browser_transport_enabled"):
        Settings()


@pytest.mark.negative
def test_ui_settings_rejects_retired_identity_workflow_toml_field(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """Reject the old UI mode name instead of accepting an alias."""
    config_path = tmp_path / "retired-identity-workflow-mode.toml"
    config_path.write_text('[ui]\nidentity_workflow = "external"\n')
    monkeypatch.setenv("ZA_CONFIG_FILE", str(config_path))

    with pytest.raises(ValidationError, match="identity_workflow"):
        Settings()


def test_browser_sessions_have_sliding_defaults() -> None:
    """Keep the advertised eight-hour sliding window within seven days."""
    settings = BrowserSessionSettings()

    assert settings.ttl_seconds == 8 * 60 * 60
    assert settings.absolute_ttl_seconds == 7 * 24 * 60 * 60
    assert settings.cleanup_batch_size == EXPECTED_SESSION_CLEANUP_BATCH_SIZE
    assert settings.slide_seconds == 30 * 60


@pytest.mark.negative
def test_external_management_requires_absolute_login_and_logout_urls() -> None:
    """Reject built-in defaults when external management is selected."""
    with pytest.raises(
        ValidationError,
        match=r"absolute HTTP\(S\) URL.*ui\.urls\.login",
    ):
        Settings(
            ui=UISettings(
                management_authentication=ManagementAuthenticationMode.EXTERNAL,
            )
        )


@pytest.mark.negative
@pytest.mark.parametrize(
    "login_url",
    [
        "https://user@frontend.example/login",
        "https://frontend.example/login?source=oauth2",
        "https://frontend.example/login#form",
    ],
)
def test_external_login_url_rejects_ambiguous_components(login_url: str) -> None:
    """Keep continuation query parameters under server control."""
    with pytest.raises(ValidationError, match="UI URLs"):
        Settings(
            ui=UISettings(
                management_authentication=ManagementAuthenticationMode.EXTERNAL,
                urls={
                    "login": login_url,
                    "logout": "https://frontend.test/logout",
                },
            ),
        )


@pytest.mark.negative
@pytest.mark.parametrize(
    "logout_url",
    [
        "https://user@frontend.example/logout",
        "https://frontend.example/logout?source=management",
        "https://frontend.example/logout#form",
    ],
)
def test_external_logout_url_rejects_ambiguous_components(logout_url: str) -> None:
    """Keep the external logout destination unambiguous."""
    with pytest.raises(ValidationError, match="UI URLs"):
        Settings(
            ui=UISettings(
                management_authentication=ManagementAuthenticationMode.EXTERNAL,
                urls={
                    "login": "https://frontend.example/login",
                    "logout": logout_url,
                },
            ),
        )


def test_workflow_token_active_key_cannot_also_be_retained() -> None:
    """Reject ambiguous active and previous keyring configuration."""
    with pytest.raises(ValidationError, match="cannot also be a previous key"):
        WorkflowTokenSettings(
            derivation_key_id="duplicate",
            previous_derivation_secrets=(
                PreviousDerivationSecretSettings(
                    key_id="duplicate",
                    secret="old-secret-at-least-32-characters",  # noqa: S106
                ),
            ),
        )


def test_workflow_token_previous_key_ids_must_be_unique() -> None:
    """Reject ambiguous duplicate identifiers in the retained keyring."""
    with pytest.raises(ValidationError, match="identifiers must be unique"):
        WorkflowTokenSettings(
            previous_derivation_secrets=(
                PreviousDerivationSecretSettings(
                    key_id="duplicate",
                    secret="first-old-secret-at-least-32-characters",  # noqa: S106
                ),
                PreviousDerivationSecretSettings(
                    key_id="duplicate",
                    secret="second-old-secret-at-least-32-characters",  # noqa: S106
                ),
            ),
        )


@pytest.mark.parametrize(
    "path",
    sorted((PROJECT_ROOT / "config").glob("*.example.toml")),
)
def test_committed_toml_profiles_are_valid(
    path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Keep every TOML profile aligned with the canonical settings model."""
    monkeypatch.setenv("ZA_CONFIG_FILE", str(path))

    Settings()


def test_configuration_catalog_contains_only_supported_profiles() -> None:
    """Keep the committed configuration catalog small and explicit."""
    assert {path.name for path in (PROJECT_ROOT / "config").glob("*.example.toml")} == {
        "development.example.toml",
        "full-server.example.toml",
        "client-credentials.example.toml",
    }


def test_client_credentials_profile_enables_only_client_credentials(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Keep the fresh machine profile limited to its originating grant."""
    monkeypatch.setenv(
        "ZA_CONFIG_FILE",
        str(PROJECT_ROOT / "config" / "client-credentials.example.toml"),
    )
    settings = Settings()

    assert settings.oauth2.enabled_grants() == {
        OAuth2GrantType.CLIENT_CREDENTIALS,
    }
    assert settings.api.interactive_auth_routes_enabled is False
    assert settings.ui.identity_workflow_is_disabled is True
    assert settings.mail.enabled is False


def test_oidc_requires_authorization_code() -> None:
    """Assert OIDC startup validation names its grant dependency."""
    oauth2_settings = OAuth2Settings().model_copy(
        update={"authorization_code_enabled": False}
    )
    with pytest.raises(ValidationError, match="authorization_code_enabled"):
        Settings(oauth2=oauth2_settings)


@pytest.mark.parametrize(
    ("authorization_code_enabled", "device_code_enabled"),
    [(True, False), (False, True)],
)
def test_refresh_tokens_accept_a_user_originating_grant(
    *,
    authorization_code_enabled: bool,
    device_code_enabled: bool,
) -> None:
    """Allow refresh-token families when a user grant can create them."""
    settings = OAuth2Settings(
        authorization_code_enabled=authorization_code_enabled,
        device_code_enabled=device_code_enabled,
        oidc_enabled=False,
    )

    assert settings.has_refresh_token_originating_grant is True
    assert settings.refresh_token_enabled is True


@pytest.mark.parametrize("client_credentials_enabled", [False, True])
def test_refresh_tokens_require_a_user_originating_grant(
    *,
    client_credentials_enabled: bool,
) -> None:
    """Reject refresh-only and Client-Credentials-plus-refresh profiles."""
    with pytest.raises(
        ValidationError,
        match=(
            "refresh_token_enabled requires authorization_code_enabled "
            "or device_code_enabled"
        ),
    ):
        OAuth2Settings(
            authorization_code_enabled=False,
            device_code_enabled=False,
            client_credentials_enabled=client_credentials_enabled,
            oidc_enabled=False,
        )


def test_machine_oauth2_grants_do_not_require_browser_sessions() -> None:
    """Allow machine-facing OAuth2 grants without the session feature."""
    oauth2 = OAuth2Settings().model_copy(
        update={
            "authorization_code_enabled": False,
            "refresh_token_enabled": False,
            "device_code_enabled": False,
            "oidc_enabled": False,
        }
    )
    settings = Settings(
        browser_session=BrowserSessionSettings(enabled=False),
        identity_workflow=IdentityWorkflowSettings(registration_enabled=False),
        oauth2=oauth2,
    )

    assert settings.oauth2.protocol_enabled is True
    assert settings.oauth2.has_enabled_grants is True
    assert settings.browser_session.enabled is False


def test_self_registration_requires_browser_sessions() -> None:
    """Reject public signup from the machine-only server profile."""
    oauth2 = OAuth2Settings().model_copy(
        update={
            "authorization_code_enabled": False,
            "refresh_token_enabled": False,
            "device_code_enabled": False,
            "oidc_enabled": False,
        }
    )

    with pytest.raises(
        ValidationError,
        match="Self-registration requires browser sessions",
    ):
        Settings(
            browser_session=BrowserSessionSettings(enabled=False),
            identity_workflow=IdentityWorkflowSettings(registration_enabled=True),
            oauth2=oauth2,
        )


@pytest.mark.parametrize(
    ("updates", "message"),
    [
        ({"signing_private_key_b64": None}, "signing_private_key_b64"),
        ({"signing_public_key_b64": None}, "signing_public_key_b64"),
        ({"signing_key_id": None}, "signing_key_id"),
    ],
)
def test_enabled_oauth2_grants_require_complete_key_configuration(
    updates: dict[str, object],
    message: str,
) -> None:
    """Reject incomplete OAuth2 signing configuration before startup."""
    oauth2 = OAuth2Settings().model_copy(update=updates)

    with pytest.raises(ValidationError, match=message):
        Settings(oauth2=oauth2)


def test_oauth2_startup_rejects_malformed_and_mismatched_keys() -> None:
    """Reject invalid Ed25519 material and unrelated key pairs at startup."""
    malformed = OAuth2Settings().model_copy(
        update={"signing_public_key_b64": "not-base64"}
    )
    mismatched = OAuth2Settings().model_copy(
        update={"signing_public_key_b64": base64.b64encode(bytes(32)).decode()}
    )

    with pytest.raises(ValidationError, match="signing_public_key_b64"):
        Settings(oauth2=malformed)
    with pytest.raises(ValidationError, match="do not form a key pair"):
        Settings(oauth2=mismatched)


@pytest.mark.parametrize(
    ("oauth2", "message"),
    [
        (
            OAuth2Settings.disabled().model_copy(
                update={"authorization_code_enabled": True}
            ),
            "authorization code support requires browser sessions",
        ),
        (
            OAuth2Settings(),
            "OpenID Connect support requires browser sessions",
        ),
        (
            OAuth2Settings.disabled().model_copy(update={"device_code_enabled": True}),
            "device code support requires browser sessions",
        ),
    ],
)
def test_interactive_oauth2_features_require_browser_sessions(
    oauth2: OAuth2Settings,
    message: str,
) -> None:
    """Reject interactive OAuth2 features without browser authentication."""
    with pytest.raises(ValidationError, match=message):
        Settings(
            browser_session=BrowserSessionSettings(enabled=False),
            oauth2=oauth2,
        )


def test_settings_sections_are_immutable_startup_values() -> None:
    """Assert feature settings cannot be changed after construction."""
    settings = Settings()

    with pytest.raises(ValidationError, match="frozen"):
        settings.browser_session.enabled = False  # type: ignore[misc]  # ty: ignore[invalid-assignment]


def test_retained_derivation_secrets_are_immutable_startup_values() -> None:
    """Prevent mutation inside the retained derivation-key collection."""
    retained = PreviousDerivationSecretSettings(
        key_id="retained",
        secret="retained-secret-at-least-32-characters",  # noqa: S106
    )
    settings = WorkflowTokenSettings(previous_derivation_secrets=(retained,))

    with pytest.raises(ValidationError, match="frozen"):
        settings.previous_derivation_secrets[0].key_id = "changed"  # type: ignore[misc]  # ty: ignore[invalid-assignment]


@pytest.mark.parametrize(
    "settings",
    [
        {"app": {"unknown": True}},
        {"api": {"unknown": True}},
        {"identity_workflow": {"unknown": True}},
        {"identity_workflow": {"email": {"unknown": True}}},
        {"identity_workflow": {"workflow_tokens": {"unknown": True}}},
        {"bootstrap": {"unknown": True}},
        {"cors": {"unknown": True}},
        {"notification_outbox": {"unknown": True}},
        {"mail": {"unknown": True}},
        {
            "oauth2": {
                "previous_public_keys": [
                    {"kid": "old", "signing_public_key_b64": "x", "unknown": True}
                ]
            }
        },
        {
            "identity_workflow": {
                "workflow_tokens": {
                    "previous_derivation_secrets": [
                        {"key_id": "old", "secret": "x" * 32, "unknown": True}
                    ]
                }
            }
        },
        {"browser_session": {"unknown": True}},
        {"browser_session": {"csrf": {"unknown": True}}},
    ],
)
def test_every_settings_section_rejects_unknown_fields(
    settings: dict[str, object],
) -> None:
    """Reject configuration typos at every nested settings boundary."""
    with pytest.raises(ValidationError, match="unknown"):
        Settings.model_validate(settings)
