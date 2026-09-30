"""Settings for browser presentation and navigation destinations."""

from enum import StrEnum
from urllib.parse import urlsplit

from pydantic import AnyHttpUrl, BaseModel, ConfigDict, field_validator

from app.settings.defaults import LOCAL_AUTH_ORIGIN


BUILTIN_LOGIN_PATH = "/login"
BUILTIN_LOGOUT_PATH = "/logout"
BUILTIN_VERIFICATION_PATH = "/verify-email"
BUILTIN_PASSWORD_RESET_PATH = "/reset-password"  # noqa: S105
BUILTIN_INVITATION_PATH = "/accept-invite"
BUILTIN_AUTHORIZATION_INTERACTION_PATH = BUILTIN_LOGIN_PATH
BUILTIN_AUTHORIZATION_CONSENT_PATH = "/consent"
BUILTIN_DEVICE_INTERACTION_PATH = "/oauth2/device/verify"
ASCII_CONTROL_LIMIT = 0x20
ASCII_DELETE = 0x7F


class UIURLs(BaseModel):
    """Browser destinations consumed by authentication workflows."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    login: str = BUILTIN_LOGIN_PATH
    logout: str = BUILTIN_LOGOUT_PATH
    verification: str = f"{LOCAL_AUTH_ORIGIN}{BUILTIN_VERIFICATION_PATH}"
    password_reset: str = f"{LOCAL_AUTH_ORIGIN}{BUILTIN_PASSWORD_RESET_PATH}"
    invitation: str = f"{LOCAL_AUTH_ORIGIN}{BUILTIN_INVITATION_PATH}"
    authorization_interaction: str = BUILTIN_AUTHORIZATION_INTERACTION_PATH
    authorization_consent: str = BUILTIN_AUTHORIZATION_CONSENT_PATH
    device_interaction: str = f"{LOCAL_AUTH_ORIGIN}{BUILTIN_DEVICE_INTERACTION_PATH}"

    @field_validator("*")
    @classmethod
    def url_must_be_unambiguous(cls, value: str) -> str:
        """Accept one safe internal path or absolute HTTP(S) URL."""
        if not value or any(
            character.isspace()
            or ord(character) < ASCII_CONTROL_LIMIT
            or ord(character) == ASCII_DELETE
            for character in value
        ):
            msg = (
                "UI URLs must not be empty or contain whitespace or control characters"
            )
            raise ValueError(msg)
        parsed = urlsplit(value)
        if parsed.query or parsed.fragment or parsed.username or parsed.password:
            msg = "UI URLs must not contain credentials, a query string, or a fragment"
            raise ValueError(msg)
        if parsed.scheme or parsed.netloc:
            try:
                return str(AnyHttpUrl(value))
            except ValueError as exc:
                msg = "UI URLs must be internal paths or absolute HTTP(S) URLs"
                raise ValueError(msg) from exc
        if not value.startswith("/") or value.startswith("//") or "\\" in value:
            msg = "Relative UI URLs must be absolute same-origin paths"
            raise ValueError(msg)
        return value


class IdentityWorkflowUIMode(StrEnum):
    """Supported identity-workflow presentation modes."""

    BUILTIN = "builtin"
    EXTERNAL = "external"
    DISABLED = "disabled"


class ManagementAuthenticationMode(StrEnum):
    """Supported login presentation modes for management pages."""

    BUILTIN = "builtin"
    EXTERNAL = "external"


class OAuth2InteractionUIMode(StrEnum):
    """Supported OAuth2 interaction presentation modes."""

    BUILTIN = "builtin"
    EXTERNAL = "external"
    DISABLED = "disabled"


class UISettings(BaseModel):
    """Settings for built-in or external browser presentation and navigation."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    identity_workflow_mode: IdentityWorkflowUIMode = IdentityWorkflowUIMode.BUILTIN
    management_authentication: ManagementAuthenticationMode = (
        ManagementAuthenticationMode.BUILTIN
    )
    oauth2_interaction: OAuth2InteractionUIMode = OAuth2InteractionUIMode.BUILTIN
    urls: UIURLs = UIURLs()
    organization_admin_enabled: bool = True
    operator_enabled: bool = True

    @property
    def identity_workflow_is_builtin(self) -> bool:
        """Return whether Zero Auth Lite renders identity-workflow pages."""
        return self.identity_workflow_mode is IdentityWorkflowUIMode.BUILTIN

    @property
    def identity_workflow_is_external(self) -> bool:
        """Return whether an external frontend explicitly owns workflow presentation."""
        return self.identity_workflow_mode is IdentityWorkflowUIMode.EXTERNAL

    @property
    def identity_workflow_is_disabled(self) -> bool:
        """Return whether no identity-workflow presentation is selected.

        The independently configured JSON transport may still expose these
        workflows to a headless client.
        """
        return self.identity_workflow_mode is IdentityWorkflowUIMode.DISABLED

    @property
    def management_authentication_is_builtin(self) -> bool:
        """Return whether management uses the built-in login and logout pages."""
        return self.management_authentication is ManagementAuthenticationMode.BUILTIN

    @property
    def management_authentication_is_external(self) -> bool:
        """Return whether management uses external login and logout pages."""
        return self.management_authentication is ManagementAuthenticationMode.EXTERNAL

    @property
    def oauth2_interaction_is_builtin(self) -> bool:
        """Return whether Zero Auth Lite owns OAuth2 interaction presentation."""
        return self.oauth2_interaction is OAuth2InteractionUIMode.BUILTIN

    @property
    def oauth2_interaction_is_external(self) -> bool:
        """Return whether an external frontend owns OAuth2 user interaction."""
        return self.oauth2_interaction is OAuth2InteractionUIMode.EXTERNAL

    @property
    def oauth2_interaction_is_disabled(self) -> bool:
        """Return whether OAuth2 user interaction is unavailable."""
        return self.oauth2_interaction is OAuth2InteractionUIMode.DISABLED
