"""Composed settings for application-owned authentication workflows."""

from pydantic import BaseModel, ConfigDict

from app.workflow_tokens.settings import WorkflowTokenSettings


class IdentityWorkflowSettings(BaseModel):
    """Registration, email, invitation, and password-reset settings."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    registration_enabled: bool = True
    workflow_tokens: WorkflowTokenSettings = WorkflowTokenSettings()
