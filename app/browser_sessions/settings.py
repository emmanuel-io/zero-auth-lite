"""Session based authentication service section settings (no I/O here).

The service supports HttpOnly cookie sessions and scoped CSRF tokens.
"""

from __future__ import annotations

from typing import Annotated

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    field_validator,
    model_validator,
    SecretStr,
)

from app.browser_sessions.enums import CookieSameSite, CSRFPattern, CSRFTokenExposure
from app.settings.defaults import LOCAL_AUTH_ORIGIN, LOCAL_ORIGINS
from app.settings.origins import normalize_http_origin


DEFAULT_SESSION_HASH_SECRET = "dev-session-id-hash-secret-for-local-server-example"  # noqa: S105
COOKIE_NAME_PATTERN = r"^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$"
FORM_CSRF_COOKIE_SUFFIX = "-form"
CookieName = Annotated[str, Field(min_length=1, pattern=COOKIE_NAME_PATTERN)]


class CSRFSettings(BaseModel):
    """CSRF protection settings."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    cookie_domain: str | None = "zero-auth-lite.localhost"
    cookie_name: CookieName = "csrftoken"
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

    @field_validator("public_origin", mode="before")
    @classmethod
    def normalize_public_origin(cls, value: object) -> object:
        """Store the public CSRF origin in its canonical form."""
        if value is None or not isinstance(value, str):
            return value
        return normalize_http_origin(name="public_origin", value=value)

    @field_validator("trusted_origins", mode="before")
    @classmethod
    def normalize_trusted_origins(cls, value: object) -> object:
        """Store trusted CSRF origins in their canonical form."""
        if not isinstance(value, (list, tuple, set, frozenset)):
            return value
        return tuple(
            normalize_http_origin(name="trusted_origins", value=origin)
            if isinstance(origin, str)
            else origin
            for origin in value
        )

    @property
    def form_cookie_name(self) -> str:
        """Return the distinct cookie name used by anonymous HTML forms."""
        return f"{self.cookie_name}{FORM_CSRF_COOKIE_SUFFIX}"


class BrowserSessionSettings(BaseModel):
    """Browser-session settings, including CSRF protection."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    enabled: bool = True
    csrf: CSRFSettings = CSRFSettings()
    cookie_domain: str | None = "zero-auth-lite.localhost"
    cookie_name: CookieName = "sessionid"
    cookie_same_site: CookieSameSite = CookieSameSite.LAX
    cookie_secure: bool = True
    hash_secret: SecretStr = Field(
        default=SecretStr(DEFAULT_SESSION_HASH_SECRET),
        min_length=32,
    )
    absolute_ttl_seconds: int = Field(default=604_800, gt=0)  # 7 days
    cleanup_batch_size: int = Field(default=100, ge=1, le=1_000)
    cleanup_interval_seconds: int = Field(default=3_600, ge=60)
    max_sessions_per_user: int = Field(default=10, ge=1, le=100)
    slide_seconds: int = Field(default=1_800, gt=0)  # 30 minutes
    ttl_seconds: int = Field(default=28_800, gt=0)  # 8 hours

    @model_validator(mode="after")
    def validate_cookie_names_and_lifetimes(self) -> BrowserSessionSettings:
        """Reject ambiguous cookie transport and invalid session lifetimes."""
        if self.cookie_name in {
            self.csrf.cookie_name,
            self.csrf.form_cookie_name,
        }:
            msg = "Session, CSRF, and form CSRF cookie names must be distinct"
            raise ValueError(msg)
        if self.ttl_seconds > self.absolute_ttl_seconds:
            msg = "ttl_seconds must not exceed absolute_ttl_seconds"
            raise ValueError(msg)
        if self.slide_seconds > self.ttl_seconds:
            msg = "slide_seconds must not exceed ttl_seconds"
            raise ValueError(msg)
        return self
