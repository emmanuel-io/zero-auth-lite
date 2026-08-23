"""User lifecycle errors exposed by the canonical server."""

from fastapi import status

from app.core.errors.base import AppError


class LastActiveOperatorError(AppError):
    """Raised when a write would remove the final usable server operator."""

    code = "LAST_ACTIVE_OPERATOR"
    message = "At least one active, verified server operator is required."
    status = status.HTTP_409_CONFLICT


class LastActiveOrganizationAdminError(AppError):
    """Raised when a write would remove the final usable organization admin."""

    code = "LAST_ACTIVE_ORGANIZATION_ADMIN"
    message = "At least one active, verified organization administrator is required."
    status = status.HTTP_409_CONFLICT


class InactiveUserInvitationError(AppError):
    """Raised when an invitation resend targets an inactive user."""

    code = "INACTIVE_USER_INVITATION"
    message = "An invitation cannot be sent to an inactive user."
    status = status.HTTP_409_CONFLICT
