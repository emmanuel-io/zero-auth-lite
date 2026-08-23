"""Settings for durable application-event delivery."""

from pydantic import BaseModel, ConfigDict, Field


class EventOutboxSettings(BaseModel):
    """Polling, leasing, retry, and retention settings for the SQL outbox."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    poll_interval_seconds: float = Field(default=1.0, gt=0)
    batch_size: int = Field(default=20, ge=1, le=100)
    lease_seconds: int = Field(default=60, ge=10)
    retry_max_seconds: int = Field(default=300, ge=1)
    retention_seconds: int = Field(default=604_800, ge=3_600)
    cleanup_interval_seconds: int = Field(default=3_600, ge=60)
    cleanup_batch_size: int = Field(default=100, ge=1, le=1_000)
    shutdown_timeout_seconds: float = Field(default=15.0, gt=0)
