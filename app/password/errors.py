"""Password policy errors independent from authentication transports."""


class PasswordPolicyViolationError(ValueError):
    """Raised when a credential does not satisfy the shared password policy."""
