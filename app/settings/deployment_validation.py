"""Deployment-hardening validation for canonical server settings."""

from __future__ import annotations

from typing import TYPE_CHECKING
from urllib.parse import urlsplit

from app.browser_sessions.settings import DEFAULT_SESSION_HASH_SECRET
from app.mail.settings import DEFAULT_MAIL_FROM_EMAIL
from app.oauth2.settings import (
    DEFAULT_AUTHORIZATION_CODE_HASH_SECRET,
    DEFAULT_TOKEN_HASH_SECRET,
)
from app.settings.defaults import DEV_OAUTH2_PRIVATE_KEY_B64, DEV_OAUTH2_PUBLIC_KEY_B64
from app.settings.origins import (
    cookie_domain_matches_hostname,
    hostname_matches_trusted_host,
    is_local_hostname,
    require_deployment_https_url,
    validate_cookie_domain,
    validate_deployment_http_origin,
)
from app.workflow_tokens.settings import DEFAULT_WORKFLOW_TOKEN_DERIVATION_SECRET


if TYPE_CHECKING:
    from app.settings.root import Settings


EXAMPLE_SECRET_PLACEHOLDER = "replace-with-at-least-32-random-characters"  # noqa: S105


def validate_deployment_settings(settings: Settings) -> None:
    """Reject local-only defaults from an explicitly deployed server."""
    insecure_values: dict[str, tuple[str | None, str | None]] = {}
    if _user_identity_workflows_enabled(settings):
        insecure_values["identity_workflow.workflow_tokens.derivation_secret"] = (
            settings.identity_workflow.workflow_tokens.derivation_secret.get_secret_value(),
            DEFAULT_WORKFLOW_TOKEN_DERIVATION_SECRET,
        )
    if settings.browser_session.enabled:
        insecure_values["browser_session.hash_secret"] = (
            settings.browser_session.hash_secret.get_secret_value(),
            DEFAULT_SESSION_HASH_SECRET,
        )
    if settings.oauth2.authorization_code_enabled:
        insecure_values["oauth2.authorization_code_hash_secret"] = (
            settings.oauth2.authorization_code_hash_secret.get_secret_value(),
            DEFAULT_AUTHORIZATION_CODE_HASH_SECRET,
        )
    if settings.oauth2.has_enabled_grants:
        insecure_values["oauth2.token_hash_secret"] = (
            settings.oauth2.token_hash_secret.get_secret_value(),
            DEFAULT_TOKEN_HASH_SECRET,
        )
        insecure_values["oauth2.signing_private_key_b64"] = (
            (
                settings.oauth2.signing_private_key_b64.get_secret_value()
                if settings.oauth2.signing_private_key_b64 is not None
                else None
            ),
            DEV_OAUTH2_PRIVATE_KEY_B64,
        )
    if settings.oauth2.protocol_enabled:
        insecure_values["oauth2.signing_public_key_b64"] = (
            settings.oauth2.signing_public_key_b64,
            DEV_OAUTH2_PUBLIC_KEY_B64,
        )
        insecure_values["oauth2.signing_key_id"] = (
            settings.oauth2.signing_key_id,
            "local-dev-key",
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
    if not settings.app.trusted_hosts:
        msg = "Deployment mode requires explicit trusted_hosts"
        raise ValueError(msg)
    _validate_deployment_network_inputs(settings)
    _validate_deployment_topology(settings)
    if _user_identity_workflows_enabled(settings) and not settings.mail.enabled:
        msg = "Deployment mode requires mail delivery for exposed identity workflows"
        raise ValueError(msg)
    if settings.mail.enabled and not (
        settings.mail.smtp_ssl or settings.mail.smtp_starttls
    ):
        msg = "Deployment mode requires SMTP SSL or STARTTLS"
        raise ValueError(msg)
    if (
        settings.mail.enabled
        and settings.mail.default_from_email == DEFAULT_MAIL_FROM_EMAIL
    ):
        msg = "Deployment mode requires an explicit mail sender address"
        raise ValueError(msg)


def _validate_deployment_network_inputs(settings: Settings) -> None:
    """Reject ineffective host checks."""
    invalid_hosts = [
        host
        for host in settings.app.trusted_hosts
        if not host.strip() or host.strip() == "*"
    ]
    if invalid_hosts:
        msg = "Deployment mode requires restrictive trusted_hosts"
        raise ValueError(msg)


def _validate_deployment_cors(settings: Settings) -> None:
    """Require configured CORS origins to describe a non-local topology."""
    for origin in settings.cors.allowed_origins:
        validate_deployment_http_origin(name="cors.allowed_origins", value=origin)


def _validate_deployment_session_topology(settings: Settings) -> None:
    """Require secure, non-local browser-session and CSRF settings."""
    if not settings.browser_session.enabled:
        return
    if not settings.browser_session.cookie_secure:
        msg = "Deployment mode requires secure browser-session cookies"
        raise ValueError(msg)
    if not settings.browser_session.csrf.cookie_secure:
        msg = "Deployment mode requires secure CSRF cookies"
        raise ValueError(msg)
    cookie_domains = {
        "browser_session.cookie_domain": settings.browser_session.cookie_domain,
        "browser_session.csrf.cookie_domain": (
            settings.browser_session.csrf.cookie_domain
        ),
    }
    for name, domain in cookie_domains.items():
        if not domain:
            continue
        normalized_domain = validate_cookie_domain(name=name, value=domain)
        if is_local_hostname(normalized_domain):
            msg = f"Deployment mode rejects local-only host in {name}"
            raise ValueError(msg)
        if settings.browser_session.csrf.public_origin is not None:
            public_hostname = urlsplit(
                settings.browser_session.csrf.public_origin
            ).hostname
            if public_hostname is None or not cookie_domain_matches_hostname(
                domain=normalized_domain,
                hostname=public_hostname,
            ):
                msg = f"{name} must domain-match browser_session.csrf.public_origin"
                raise ValueError(msg)
    csrf_origins = {
        "browser_session.csrf.trusted_origins": (
            settings.browser_session.csrf.trusted_origins
        ),
    }
    if settings.browser_session.csrf.public_origin is not None:
        csrf_origins["browser_session.csrf.public_origin"] = (
            settings.browser_session.csrf.public_origin,
        )
    for name, origins in csrf_origins.items():
        for origin in origins:
            validate_deployment_http_origin(name=name, value=origin)


def _validate_deployment_public_urls(settings: Settings) -> None:
    """Require HTTPS and non-local OAuth2 and workflow public URLs."""
    public_urls: list[tuple[str, str, str]] = []
    if settings.oauth2.protocol_enabled:
        public_urls.append(("oauth2.issuer", settings.oauth2.issuer, "OAuth2 issuer"))
    if settings.default_redirect_url is not None:
        public_urls.append(
            (
                "default_redirect_url",
                str(settings.default_redirect_url),
                "default redirect URL",
            )
        )
    if (
        not settings.ui.identity_workflow_is_disabled
        or settings.api.interactive_auth_routes_enabled
    ):
        public_urls.extend(
            (f"ui.urls.{name}", value, f"{name} UI URL")
            for name, value in (
                ("verification", settings.ui.urls.verification),
                ("password_reset", settings.ui.urls.password_reset),
                ("invitation", settings.ui.urls.invitation),
            )
        )
    if (
        settings.ui.management_authentication_is_external
        and settings.browser_session.enabled
    ):
        public_urls.extend(
            (f"ui.urls.{name}", value, f"{name} UI URL")
            for name, value in (
                ("login", settings.ui.urls.login),
                ("logout", settings.ui.urls.logout),
            )
        )
    if (
        settings.ui.oauth2_interaction_is_external
        and settings.oauth2.authorization_code_enabled
    ):
        public_urls.append(
            (
                "ui.urls.authorization_interaction",
                settings.ui.urls.authorization_interaction,
                "authorization interaction UI URL",
            )
        )
    if settings.oauth2.device_code_enabled:
        public_urls.append(
            (
                "ui.urls.device_interaction",
                settings.ui.urls.device_interaction,
                "device interaction UI URL",
            )
        )
    for name, value, description in public_urls:
        require_deployment_https_url(name=name, value=value, description=description)


def _validate_deployment_topology(settings: Settings) -> None:
    """Validate unambiguous deployment topology invariants."""
    _validate_deployment_cors(settings)
    _validate_deployment_session_topology(settings)
    _validate_deployment_public_urls(settings)
    public_hosts: list[tuple[str, str]] = []
    if (
        settings.browser_session.enabled
        and settings.browser_session.csrf.public_origin is not None
    ):
        public_hosts.append(
            (
                "browser_session.csrf.public_origin",
                settings.browser_session.csrf.public_origin,
            )
        )
    if settings.oauth2.protocol_enabled:
        public_hosts.append(("oauth2.issuer", settings.oauth2.issuer))
    for name, url in public_hosts:
        hostname = urlsplit(url).hostname
        if hostname is None or not any(
            hostname_matches_trusted_host(hostname, trusted_host)
            for trusted_host in settings.app.trusted_hosts
        ):
            msg = f"{name} host must be accepted by app.trusted_hosts"
            raise ValueError(msg)


def _user_identity_workflows_enabled(settings: Settings) -> bool:
    """Return whether any user identity workflow capability remains enabled."""
    return (
        not settings.ui.identity_workflow_is_disabled
        or settings.api.interactive_auth_routes_enabled
        or settings.browser_session.enabled
        or settings.oauth2.refresh_token_enabled
    )
