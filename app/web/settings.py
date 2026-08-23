"""Settings for the built-in Zero Auth Lite browser interface."""

from enum import StrEnum

from pydantic import AnyHttpUrl, BaseModel, ConfigDict


class AuthenticationUIMode(StrEnum):
    """Supported authentication presentation modes."""

    BUILTIN = "builtin"
    EXTERNAL = "external"


class OAuth2InteractionUIMode(StrEnum):
    """Supported OAuth2 interaction presentation modes."""

    BUILTIN = "builtin"
    DISABLED = "disabled"


class UISettings(BaseModel):
    """Global settings for Zero Auth Lite-owned browser presentation."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    authentication: AuthenticationUIMode = AuthenticationUIMode.BUILTIN
    oauth2_interaction: OAuth2InteractionUIMode = OAuth2InteractionUIMode.BUILTIN
    external_login_url: AnyHttpUrl | None = None

    @property
    def authentication_is_builtin(self) -> bool:
        """Return whether Zero Auth Lite owns authentication presentation."""
        return self.authentication is AuthenticationUIMode.BUILTIN

    @property
    def oauth2_interaction_is_builtin(self) -> bool:
        """Return whether Zero Auth Lite owns OAuth2 interaction presentation."""
        return self.oauth2_interaction is OAuth2InteractionUIMode.BUILTIN
