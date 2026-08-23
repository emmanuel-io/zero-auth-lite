"""Composed settings for application-owned authentication workflows."""

from pydantic import AnyHttpUrl, BaseModel, ConfigDict, field_validator

from app.auth_tokens.settings import AuthTokenSettings
from app.settings.defaults import LOCAL_AUTH_ORIGIN
from app.settings.origins import validate_absolute_http_origin


class AuthEmailSettings(BaseModel):
    """Settings for verification, invitation, and password-reset links."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    frontend_base_url: AnyHttpUrl

    @field_validator("frontend_base_url")
    @classmethod
    def frontend_base_url_must_be_origin(cls, value: AnyHttpUrl) -> AnyHttpUrl:
        """Reject URL components that cannot belong to a frontend origin."""
        validate_absolute_http_origin(name="frontend_base_url", value=str(value))
        return value


class AuthSettings(BaseModel):
    """Registration, email, invitation, and password-reset settings."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    registration_enabled: bool = True
    email: AuthEmailSettings = AuthEmailSettings(
        frontend_base_url=AnyHttpUrl(LOCAL_AUTH_ORIGIN)
    )
    tokens: AuthTokenSettings = AuthTokenSettings()
