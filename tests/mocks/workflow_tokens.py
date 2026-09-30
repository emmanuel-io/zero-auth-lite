# ruff: noqa: D102, D107
"""In-memory workflow-token fake used by service tests."""

from dataclasses import asdict, replace
from datetime import datetime

from app.workflow_tokens.dtos import WorkflowTokenCreateDTO, WorkflowTokenReadDTO
from app.workflow_tokens.enums import WorkflowTokenPurpose


class MemoryWorkflowTokenStore:
    """Keep workflow tokens in memory for isolated behavior tests."""

    def __init__(self) -> None:
        self._rows: dict[int, WorkflowTokenReadDTO] = {}
        self._next_id = 1

    async def replace_active(
        self, data: WorkflowTokenCreateDTO
    ) -> WorkflowTokenReadDTO:
        now = datetime.now(data.expires_at.tzinfo)
        for token_id, row in list(self._rows.items()):
            if (
                row.user_email_id == data.user_email_id
                and row.purpose == data.purpose
                and row.used_at is None
            ):
                self._rows[token_id] = replace(row, used_at=now)
        row = WorkflowTokenReadDTO(**asdict(data), id=self._next_id)
        self._next_id += 1
        self._rows[row.id] = row
        return row

    async def create_for_event(
        self, data: WorkflowTokenCreateDTO
    ) -> WorkflowTokenReadDTO | None:
        if data.source_event_id is None or data.source_event_occurred_at is None:
            msg = "Event tokens require their id and occurrence time."
            raise ValueError(msg)
        ordering = (data.source_event_occurred_at, data.source_event_id)
        for row in self._rows.values():
            if (
                row.user_email_id == data.user_email_id
                and row.purpose == data.purpose
                and row.source_event_id is not None
                and row.source_event_occurred_at is not None
                and (row.source_event_occurred_at, row.source_event_id) > ordering
            ):
                return None
        return await self.replace_active(data)

    async def read_by_source_event_id(
        self, source_event_id: str
    ) -> WorkflowTokenReadDTO | None:
        return next(
            (
                row
                for row in self._rows.values()
                if row.source_event_id == source_event_id
            ),
            None,
        )

    async def renew_for_event(
        self, *, source_event_id: str, expires_at: datetime
    ) -> WorkflowTokenReadDTO | None:
        """Extend an unused token created by the requested event."""
        for token_id, row in self._rows.items():
            if row.source_event_id == source_event_id and row.used_at is None:
                renewed = replace(row, expires_at=expires_at)
                self._rows[token_id] = renewed
                return renewed
        return None

    async def consume(
        self,
        *,
        token_hash: str,
        purposes: frozenset[WorkflowTokenPurpose],
        now: datetime,
    ) -> WorkflowTokenReadDTO | None:
        for token_id, row in self._rows.items():
            if (
                row.token_hash == token_hash
                and row.purpose in purposes
                and row.used_at is None
                and row.expires_at > now
            ):
                consumed = replace(row, used_at=now)
                self._rows[token_id] = consumed
                return consumed
        return None
