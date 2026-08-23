"""App section settings."""

from typing import Literal

from pydantic import BaseModel, ConfigDict


class AppSettings(BaseModel):
    """Application runtime settings."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    environment: Literal["development", "deployment"] = "development"
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"] = "INFO"
    trusted_proxy_ips: tuple[str, ...] = ()
    trusted_hosts: tuple[str, ...] = ()
