"""Mail subsystem exceptions."""

from app.core.errors.base import AppError


class MailError(AppError):
    """Base exception for mail delivery failures."""

    code = "MAIL_ERROR"
    message = "Mail delivery failed."


class MailDeliveryError(MailError):
    """Raised when a provider cannot deliver a message."""

    code = "MAIL_DELIVERY_ERROR"
    message = "Mail provider could not deliver the message."


class MailTemplateError(MailError):
    """Raised when an email template cannot be rendered."""

    code = "MAIL_TEMPLATE_ERROR"
    message = "Mail template could not be rendered."
