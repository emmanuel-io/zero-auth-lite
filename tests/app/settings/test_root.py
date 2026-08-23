"""Tests for server configuration loading and validation."""

import base64
import tomllib
from pathlib import Path

import pytest
from app.auth_tokens.settings import (
    AuthTokenSettings,
    PreviousDerivationSecretSettings,
)
from app.browser_sessions.settings import SessionSettings
from app.oauth2.settings import OAuth2GrantType, OAuth2Settings
from app.settings.auth import AuthEmailSettings
from app.settings.cors import CorsSettings
from app.settings.root import Settings
from app.web.settings import AuthenticationUIMode, UISettings
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from pydantic import ValidationError
from pydantic_settings import SettingsError


pytestmark = pytest.mark.unit
PROJECT_ROOT = Path(__file__).parents[3]
SNOWFLAKE_NODE_ID = 7
EXPECTED_SESSION_CLEANUP_BATCH_SIZE = 100


def deployment_settings_kwargs() -> dict[str, object]:
    """Return a valid deployment baseline for focused negative tests."""
    return {
        "app": {"environment": "deployment", "trusted_hosts": ["auth.example"]},
        "cors": {"allowed_origins": ["https://app.example"]},
        "session": {
            "cookie_domain": "auth.example",
            "id_hash_secret": "session-secret-at-least-32-characters",
            "csrf": {
                "cookie_domain": "auth.example",
                "public_origin": "https://auth.example",
                "trusted_origins": ["https://app.example"],
            },
        },
        "oauth2": OAuth2Settings.disabled(),
        "auth": {
            "email": {"frontend_base_url": "https://auth.example"},
            "tokens": {"derivation_secret": "workflow-secret-at-least-32-characters"},
        },
    }


def deployment_oauth2_settings(*, jwt_issuer: str) -> OAuth2Settings:
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
        prv_key_b64=base64.b64encode(private_bytes).decode(),
        pub_key_b64=base64.b64encode(public_bytes).decode(),
        authorization_code_hash_secret="code-secret-at-least-32-characters",  # noqa: S106
        token_hash_secret="token-secret-at-least-32-characters",  # noqa: S106
        jwt_key_id="deployment-key",
        jwt_issuer=jwt_issuer,
    )


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


@pytest.mark.negative
@pytest.mark.parametrize(
    "frontend_base_url",
    [
        "https://user@app.example",
        "https://user:password@app.example",
        "https://app.example/workflows",
        "https://app.example?source=email",
        "https://app.example#workflow",
    ],
)
def test_email_frontend_base_url_requires_exact_origin(
    frontend_base_url: str,
) -> None:
    """Reject URL components that would corrupt or expose workflow links."""
    with pytest.raises(ValidationError, match=r"absolute HTTP.*origin"):
        AuthEmailSettings(frontend_base_url=frontend_base_url)


def test_email_frontend_base_url_is_required_for_external_ui_links() -> None:
    """Do not construct email workflows without an absolute consumer origin."""
    with pytest.raises(ValidationError, match="frontend_base_url"):
        AuthEmailSettings()


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


def test_settings_loads_an_explicit_toml_file(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """Select a TOML file through the dedicated loader environment variable."""
    config_path = tmp_path / "selected.toml"
    config_path.write_text(
        """
[session]
cookie_name = "toml-session"

[auth.tokens]
previous_derivation_secrets = [
  { key_id = "retained", secret = "retained-secret-at-least-32-characters" },
]
"""
    )
    monkeypatch.setenv("ZA_CONFIG_FILE", str(config_path))

    settings = Settings()

    assert settings.session.cookie_name == "toml-session"
    retained = settings.auth.tokens.derivation_secret_for("retained")
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
jwt_audience = "toml-audience"
jwt_key_id = "toml-key"

[session]
cookie_name = "toml-session"
"""
    )
    monkeypatch.setenv("ZA_CONFIG_FILE", str(config_path))
    monkeypatch.setenv("ZA_OAUTH2__JWT_AUDIENCE", "environment-audience")
    monkeypatch.setenv("ZA_SESSION__COOKIE_NAME", "environment-session")

    settings = Settings(oauth2={"jwt_audience": "python-audience"})

    assert settings.oauth2.jwt_audience == "python-audience"
    assert settings.oauth2.jwt_key_id == "toml-key"
    assert settings.session.cookie_name == "environment-session"
    assert settings.session.ttl_seconds == SessionSettings().ttl_seconds


def test_settings_reads_database_environment_variables(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Load the database path and SQL logging flag from root settings."""
    monkeypatch.setenv("ZA_DB_PATH", "tmp/zero-auth-lite.db")
    monkeypatch.setenv("ZA_DB_ECHO", "true")
    settings = Settings()

    assert settings.db_path == Path("tmp/zero-auth-lite.db")
    assert settings.db_echo is True


def test_settings_read_runtime_and_snowflake_worker_environment(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """Load an optional fixed node and the shared process runtime directory."""
    monkeypatch.setenv("ZA_SNOWFLAKE_NODE_ID", str(SNOWFLAKE_NODE_ID))
    monkeypatch.setenv("ZA_RUNTIME_DIR", str(tmp_path))

    settings = Settings()

    assert settings.snowflake_node_id == SNOWFLAKE_NODE_ID
    assert settings.runtime_dir == tmp_path


@pytest.mark.negative
def test_settings_reject_invalid_snowflake_node_id(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Reject a node identifier that does not fit the 10-bit field."""
    monkeypatch.setenv("ZA_SNOWFLAKE_NODE_ID", "1024")

    with pytest.raises(ValidationError, match="snowflake_node_id"):
        Settings()


def test_nested_environment_override_preserves_section_defaults(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Change one nested value without rebuilding the section from other defaults."""
    monkeypatch.setenv("ZA_OAUTH2__JWT_AUDIENCE", "custom-audience")
    monkeypatch.setenv("ZA_SESSION__COOKIE_NAME", "custom-session")
    settings = Settings()

    assert settings.oauth2.jwt_audience == "custom-audience"
    assert settings.oauth2.enabled_grants() == OAuth2Settings().enabled_grants()
    assert settings.oauth2.oidc_enabled is True
    assert settings.oauth2.jwks_enabled is True
    assert settings.session.cookie_name == "custom-session"
    assert settings.session.csrf.public_origin is not None


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
        OAuth2Settings(jwt_issuer=issuer)


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
        OAuth2Settings(jwt_issuer=issuer)


def test_auth_token_derivation_keyring_loads_from_environment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Load the active derivation key and retained rotation keys explicitly."""
    monkeypatch.setenv("ZA_AUTH__TOKENS__DERIVATION_KEY_ID", "2026-09")
    monkeypatch.setenv(
        "ZA_AUTH__TOKENS__PREVIOUS_DERIVATION_SECRETS",
        '[{"key_id":"2026-08","secret":"retained-secret-at-least-32-characters"}]',
    )

    settings = Settings()

    assert settings.auth.tokens.derivation_key_id == "2026-09"
    retained = settings.auth.tokens.derivation_secret_for("2026-08")
    assert retained is not None
    assert retained.get_secret_value() == "retained-secret-at-least-32-characters"


def test_public_registration_policy_loads_from_environment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Allow deployments to close public signup explicitly."""
    monkeypatch.setenv("ZA_AUTH__REGISTRATION_ENABLED", "false")

    settings = Settings()

    assert settings.auth.registration_enabled is False


@pytest.mark.negative
def test_deployment_mode_rejects_local_security_defaults() -> None:
    """Prevent an explicitly deployed server from reusing public local secrets."""
    with pytest.raises(ValidationError, match="development secrets"):
        Settings(app={"environment": "deployment"})


def test_deployment_mode_accepts_explicit_non_local_topology() -> None:
    """Accept a complete deployment snapshot with non-local public hosts."""
    settings = Settings(**deployment_settings_kwargs())

    assert settings.app.environment == "deployment"


@pytest.mark.negative
def test_deployment_mode_rejects_wildcard_trusted_host() -> None:
    """Prevent deployment mode from disabling host-header validation."""
    values = deployment_settings_kwargs()
    values["app"] = {"environment": "deployment", "trusted_hosts": ["*"]}

    with pytest.raises(ValidationError, match="restrictive trusted_hosts"):
        Settings(**values)


@pytest.mark.negative
def test_deployment_mode_rejects_invalid_trusted_proxy_network() -> None:
    """Fail closed when a configured trusted proxy network is malformed."""
    values = deployment_settings_kwargs()
    values["app"] = {
        "environment": "deployment",
        "trusted_hosts": ["auth.example"],
        "trusted_proxy_ips": ["not-a-network"],
    }

    with pytest.raises(ValidationError, match=r"app\.trusted_proxy_ips"):
        Settings(**values)


@pytest.mark.negative
def test_deployment_mode_rejects_committed_secret_placeholder() -> None:
    """Reject the syntactically valid placeholder distributed in env examples."""
    values = deployment_settings_kwargs()
    merge_setting_updates(
        values,
        {"session": {"id_hash_secret": "replace-with-at-least-32-random-characters"}},
    )

    with pytest.raises(ValidationError, match=r"session\.id_hash_secret"):
        Settings(**values)


@pytest.mark.negative
def test_device_flow_requires_builtin_verification_ui() -> None:
    """Reject a device flow that would advertise an unavailable verification URI."""
    with pytest.raises(ValidationError, match=r"device code.*built-in UI"):
        Settings(ui={"oauth2_interaction": "disabled"})


@pytest.mark.negative
def test_deployment_mode_requires_mail_delivery() -> None:
    """Require mail delivery for public authentication workflows."""
    mail_values = deployment_settings_kwargs()
    mail_values["mail"] = {"enabled": False}
    with pytest.raises(ValidationError, match="mail delivery"):
        Settings(**mail_values)


@pytest.mark.negative
def test_server_requires_an_authentication_mechanism() -> None:
    """Reject a canonical server with neither sessions nor OAuth2."""
    with pytest.raises(ValidationError, match="authentication mechanism"):
        Settings(
            session=SessionSettings(enabled=False),
            oauth2=OAuth2Settings.disabled(),
        )


@pytest.mark.negative
def test_deployment_mode_requires_secure_csrf_cookie() -> None:
    """Reject a CSRF cookie that can cross a plaintext transport."""
    values = deployment_settings_kwargs()
    merge_setting_updates(values, {"session": {"csrf": {"cookie_secure": False}}})

    with pytest.raises(ValidationError, match="secure CSRF cookies"):
        Settings(**values)


@pytest.mark.negative
def test_deployment_mode_requires_https_public_urls() -> None:
    """Require TLS for the OAuth2 issuer and workflow frontend URL."""
    issuer_values = deployment_settings_kwargs()
    issuer_values["oauth2"] = deployment_oauth2_settings(
        jwt_issuer="http://auth.example"
    )
    with pytest.raises(ValidationError, match="HTTPS OAuth2 issuer"):
        Settings(**issuer_values)

    frontend_values = deployment_settings_kwargs()
    frontend_values["auth"] = {
        "email": {"frontend_base_url": "http://app.example"},
        "tokens": {"derivation_secret": "workflow-secret-at-least-32-characters"},
    }
    with pytest.raises(ValidationError, match="HTTPS email frontend URL"):
        Settings(**frontend_values)

    login_values = deployment_settings_kwargs()
    login_values["ui"] = {
        "authentication": "external",
        "external_login_url": "http://frontend.example/login",
    }
    with pytest.raises(ValidationError, match="HTTPS external login URL"):
        Settings(**login_values)


@pytest.mark.negative
@pytest.mark.parametrize(
    ("updates", "setting_name"),
    [
        (
            {"cors": {"allowed_origins": ["http://localhost:3000"]}},
            "cors.allowed_origins",
        ),
        (
            {"session": {"cookie_domain": "zero-auth-lite.localhost"}},
            "session.cookie_domain",
        ),
        (
            {"session": {"csrf": {"cookie_domain": ".localhost"}}},
            "session.csrf.cookie_domain",
        ),
        (
            {"session": {"csrf": {"public_origin": "https://auth.localhost"}}},
            "session.csrf.public_origin",
        ),
        (
            {"session": {"csrf": {"trusted_origins": ["https://127.0.0.1"]}}},
            "session.csrf.trusted_origins",
        ),
        (
            {"auth": {"email": {"frontend_base_url": "https://[::1]"}}},
            "auth.email.frontend_base_url",
        ),
        (
            {"ui": {"external_login_url": "https://frontend.localhost/login"}},
            "ui.external_login_url",
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
        Settings(**values)


@pytest.mark.negative
@pytest.mark.parametrize(
    ("updates", "setting_name"),
    [
        (
            {"cors": {"allowed_origins": ["http://app.example"]}},
            "cors.allowed_origins",
        ),
        (
            {"session": {"csrf": {"public_origin": "http://auth.example"}}},
            "session.csrf.public_origin",
        ),
        (
            {"session": {"csrf": {"trusted_origins": ["http://app.example"]}}},
            "session.csrf.trusted_origins",
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
        Settings(**values)


@pytest.mark.negative
def test_deployment_mode_rejects_local_oauth2_issuer() -> None:
    """Reject a loopback or localhost issuer even when it uses HTTPS."""
    values = deployment_settings_kwargs()
    values["oauth2"] = deployment_oauth2_settings(jwt_issuer="https://auth.localhost")

    with pytest.raises(ValidationError, match=r"oauth2\.jwt_issuer"):
        Settings(**values)


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
    merge_setting_updates(values, {"session": {"csrf": csrf}})

    with pytest.raises(ValidationError, match=setting_name):
        Settings(**values)


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
    assert Settings().ui.authentication_is_builtin is True
    monkeypatch.setenv("ZA_UI__AUTHENTICATION", "external")
    monkeypatch.setenv(
        "ZA_UI__EXTERNAL_LOGIN_URL",
        "https://frontend.example/login",
    )

    settings = Settings()

    assert settings.ui.authentication is AuthenticationUIMode.EXTERNAL
    assert str(settings.ui.external_login_url) == "https://frontend.example/login"


def test_browser_sessions_have_sliding_defaults() -> None:
    """Keep the advertised eight-hour sliding window within seven days."""
    settings = SessionSettings()

    assert settings.ttl_seconds == 8 * 60 * 60
    assert settings.absolute_ttl_seconds == 7 * 24 * 60 * 60
    assert settings.cleanup_batch_size == EXPECTED_SESSION_CLEANUP_BATCH_SIZE
    assert settings.slide_seconds == 30 * 60


@pytest.mark.negative
def test_external_auth_requires_login_url_for_interactive_oauth2() -> None:
    """Reject an external authentication transport with no login destination."""
    with pytest.raises(ValidationError, match="external_login_url"):
        Settings(ui=UISettings(authentication=AuthenticationUIMode.EXTERNAL))


@pytest.mark.negative
@pytest.mark.parametrize(
    "external_login_url",
    [
        "https://user@frontend.example/login",
        "https://frontend.example/login?source=oauth2",
        "https://frontend.example/login#form",
    ],
)
def test_external_login_url_rejects_ambiguous_components(
    external_login_url: str,
) -> None:
    """Keep continuation query parameters under server control."""
    with pytest.raises(ValidationError, match="external_login_url"):
        Settings(
            ui=UISettings(
                authentication=AuthenticationUIMode.EXTERNAL,
                external_login_url=external_login_url,
            ),
        )


def test_auth_token_active_key_cannot_also_be_retained() -> None:
    """Reject ambiguous active and previous keyring configuration."""
    with pytest.raises(ValidationError, match="cannot also be a previous key"):
        AuthTokenSettings(
            derivation_key_id="duplicate",
            previous_derivation_secrets=(
                PreviousDerivationSecretSettings(
                    key_id="duplicate",
                    secret="old-secret-at-least-32-characters",  # noqa: S106
                ),
            ),
        )


def test_auth_token_previous_key_ids_must_be_unique() -> None:
    """Reject ambiguous duplicate identifiers in the retained keyring."""
    with pytest.raises(ValidationError, match="identifiers must be unique"):
        AuthTokenSettings(
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
        OAuth2GrantType.client_credentials,
    }


def test_oidc_requires_authorization_code() -> None:
    """Assert OIDC startup validation names its grant dependency."""
    oauth2_settings = OAuth2Settings().model_copy(
        update={"authorization_code_enabled": False}
    )
    with pytest.raises(ValidationError, match="authorization_code_enabled"):
        Settings(oauth2=oauth2_settings)


def test_machine_oauth2_grants_do_not_require_browser_sessions() -> None:
    """Allow machine-facing OAuth2 grants without the session feature."""
    oauth2 = OAuth2Settings().model_copy(
        update={
            "authorization_code_enabled": False,
            "device_code_enabled": False,
            "oidc_enabled": False,
        }
    )
    settings = Settings(
        session=SessionSettings(enabled=False),
        oauth2=oauth2,
    )

    assert settings.oauth2.protocol_enabled is True
    assert settings.oauth2.has_enabled_grants is True
    assert settings.session.enabled is False


@pytest.mark.parametrize(
    ("updates", "message"),
    [
        ({"prv_key_b64": None}, "prv_key_b64"),
        ({"pub_key_b64": None}, "pub_key_b64"),
        ({"jwt_key_id": None}, "jwt_key_id"),
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
    malformed = OAuth2Settings().model_copy(update={"pub_key_b64": "not-base64"})
    mismatched = OAuth2Settings().model_copy(
        update={"pub_key_b64": base64.b64encode(bytes(32)).decode()}
    )

    with pytest.raises(ValidationError, match="pub_key_b64"):
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
            session=SessionSettings(enabled=False),
            oauth2=oauth2,
        )


def test_settings_sections_are_immutable_startup_values() -> None:
    """Assert feature settings cannot be changed after construction."""
    settings = Settings()

    with pytest.raises(ValidationError, match="frozen"):
        settings.session.enabled = False


def test_retained_derivation_secrets_are_immutable_startup_values() -> None:
    """Prevent mutation inside the retained derivation-key collection."""
    retained = PreviousDerivationSecretSettings(
        key_id="retained",
        secret="retained-secret-at-least-32-characters",  # noqa: S106
    )
    settings = AuthTokenSettings(previous_derivation_secrets=(retained,))

    with pytest.raises(ValidationError, match="frozen"):
        settings.previous_derivation_secrets[0].key_id = "changed"


@pytest.mark.parametrize(
    "settings",
    [
        {"app": {"unknown": True}},
        {"auth": {"unknown": True}},
        {"auth": {"email": {"unknown": True}}},
        {"auth": {"tokens": {"unknown": True}}},
        {"bootstrap": {"unknown": True}},
        {"cors": {"unknown": True}},
        {"events": {"unknown": True}},
        {"mail": {"unknown": True}},
        {
            "oauth2": {
                "previous_public_keys": [
                    {"kid": "old", "pub_key_b64": "x", "unknown": True}
                ]
            }
        },
        {
            "auth": {
                "tokens": {
                    "previous_derivation_secrets": [
                        {"key_id": "old", "secret": "x" * 32, "unknown": True}
                    ]
                }
            }
        },
        {"session": {"unknown": True}},
        {"session": {"csrf": {"unknown": True}}},
    ],
)
def test_every_settings_section_rejects_unknown_fields(
    settings: dict[str, object],
) -> None:
    """Reject configuration typos at every nested settings boundary."""
    with pytest.raises(ValidationError, match="unknown"):
        Settings.model_validate(settings)
