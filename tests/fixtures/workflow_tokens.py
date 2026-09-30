"""Shared workflow-token helpers for black-box route tests."""

from unittest.mock import patch

from app.db.models.workflow_token import UserWorkflowTokenDB
from app.notifications.dispatcher import dispatch_pending_once
from app.workflow_tokens.enums import WorkflowTokenPurpose
from app.workflow_tokens.service import WorkflowTokenService
from fastapi import FastAPI
from sqlalchemy import select


class SuccessfulMailService:
    """Mail fake accepting workflow delivery without external infrastructure."""

    async def send_template(self, _message: object) -> None:
        """Accept the prepared message."""


async def notification_token(app: FastAPI, purpose: WorkflowTokenPurpose) -> str:
    """Drain notifications and reproduce the token created for one event."""
    settings = app.state.settings.model_copy(
        update={"mail": app.state.settings.mail.model_copy(update={"enabled": True})}
    )
    with patch(
        "app.notifications.dispatcher.build_mail_service",
        return_value=SuccessfulMailService(),
    ):
        await dispatch_pending_once(app.state.core_session_factory, settings)
    async with app.state.core_session_factory() as session:
        row = await session.scalar(
            select(UserWorkflowTokenDB)
            .where(UserWorkflowTokenDB.purpose == purpose)
            .order_by(UserWorkflowTokenDB.id.desc())
        )
        assert row is not None
        assert row.source_event_id is not None
        assert row.source_event_occurred_at is not None
        token = await WorkflowTokenService(
            db_session=session,
            settings=app.state.settings.identity_workflow.workflow_tokens,
        ).issue_token_for_event(
            event_id=row.source_event_id,
            event_occurred_at=row.source_event_occurred_at,
            user_email_id=row.user_email_id,
            purpose=WorkflowTokenPurpose(row.purpose),
        )
        assert token is not None
        return token
