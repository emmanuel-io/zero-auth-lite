"""Workflow-token persistence data shapes."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING


if TYPE_CHECKING:
    from datetime import datetime

    from app.workflow_tokens.enums import WorkflowTokenPurpose


@dataclass(frozen=True, slots=True)
class WorkflowTokenCreateDTO:
    """Workflow-token creation data."""

    user_email_id: int
    purpose: WorkflowTokenPurpose
    token_hash: str
    expires_at: datetime
    source_event_id: str | None = field(default=None, kw_only=True)
    source_event_occurred_at: datetime | None = field(default=None, kw_only=True)
    derivation_key_id: str | None = field(default=None, kw_only=True)


@dataclass(frozen=True, slots=True)
class WorkflowTokenReadDTO(WorkflowTokenCreateDTO):
    """Stored workflow token."""

    id: int
    used_at: datetime | None = None
