"""Session based authentication service section settings (no I/O here).

The service supports HttpOnly cookie sessions and scoped CSRF tokens.
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field, model_validator, SecretStr

from app.browser_sessions.enums import CookieSameSite, CSRFPattern, CSRFTokenExposure
from app.settings.defaults import LOCAL_AUTH_ORIGIN, LOCAL_ORIGINS


DEFAULT_SESSION_ID_HASH_SECRET = "dev-session-id-hash-secret-for-local-server-example"  # noqa: S105


class CSRFSettings(BaseModel):
    """CSRF protection settings."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    cookie_domain: str | None = "zero-auth-lite.localhost"
    cookie_name: str = "csrftoken"
    cookie_same_site: CookieSameSite = CookieSameSite.LAX
    cookie_secure: bool = True
    expose_token: CSRFTokenExposure = CSRFTokenExposure.HEADER
    header_name: str = "X-CSRF-Token"
    origin_check_enabled: bool = True
    pattern: CSRFPattern = CSRFPattern.SYNCHRONIZER_TOKEN
    public_origin: str | None = LOCAL_AUTH_ORIGIN
    trusted_origins: tuple[str, ...] = LOCAL_ORIGINS
    ttl_seconds: int = Field(
        default=28_800,
        gt=0,
        description="Lifetime of the stateless pre-session CSRF cookie.",
    )  # 8 hours


class SessionSettings(BaseModel):
    """Browser-session settings, including CSRF protection."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    enabled: bool = True
    csrf: CSRFSettings = CSRFSettings()
    cookie_domain: str | None = "zero-auth-lite.localhost"
    cookie_name: str = "sessionid"
    cookie_same_site: CookieSameSite = CookieSameSite.LAX
    cookie_secure: bool = True
    id_hash_secret: SecretStr = Field(
        default=SecretStr(DEFAULT_SESSION_ID_HASH_SECRET),
        min_length=32,
    )
    absolute_ttl_seconds: int = Field(default=604_800, gt=0)  # 7 days
    cleanup_batch_size: int = Field(default=100, ge=1, le=1_000)
    max_sessions_per_user: int = Field(default=10, ge=1, le=100)
    slide_seconds: int = Field(default=1_800, gt=0)  # 30 minutes
    ttl_seconds: int = Field(default=28_800, gt=0)  # 8 hours

    @model_validator(mode="after")
    def validate_lifetimes(self) -> SessionSettings:
        """Ensure sliding sessions cannot outlive their absolute lifetime."""
        if self.ttl_seconds > self.absolute_ttl_seconds:
            msg = "ttl_seconds must not exceed absolute_ttl_seconds"
            raise ValueError(msg)
        if self.slide_seconds > self.ttl_seconds:
            msg = "slide_seconds must not exceed ttl_seconds"
            raise ValueError(msg)
        return self
