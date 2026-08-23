"""Mail subsystem exceptions."""

from app.core.errors.base import AppError


class MailError(AppError):
    """Base exception for transactional mail failures."""

    code = "MAIL_ERROR"
    message = "Transactional mail failed."


class MailConfigurationError(MailError):
    """Raised when mail settings cannot build a working provider."""

    code = "MAIL_CONFIGURATION_ERROR"
    message = "Mail provider is not configured correctly."


class MailDeliveryError(MailError):
    """Raised when a provider cannot deliver a message."""

    code = "MAIL_DELIVERY_ERROR"
    message = "Mail provider could not deliver the message."


class MailTemplateError(MailError):
    """Raised when an email template cannot be rendered."""

    code = "MAIL_TEMPLATE_ERROR"
    message = "Mail template could not be rendered."
