"""Exceptions for single-use workflow tokens."""

from fastapi import status

from app.core.errors.base import AppError


class InvalidWorkflowTokenError(AppError):
    """Raised when a workflow token is unknown, expired, or already used."""

    code = "INVALID_WORKFLOW_TOKEN"
    message = "Workflow token is invalid or expired."
    status = status.HTTP_400_BAD_REQUEST


class WorkflowTokenDerivationKeyError(RuntimeError):
    """Raised when a persisted event token cannot be reproduced safely."""
