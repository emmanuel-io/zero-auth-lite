"""Application password policy validation."""

import re
from typing import Annotated, Final

from pydantic import AfterValidator, StringConstraints

from app.password.errors import PasswordPolicyViolationError


MIN_PASSWORD_LENGTH: Final[int] = 8
MAX_PASSWORD_LENGTH: Final[int] = 1_024


def _password_policy_error(password: str) -> str | None:
    """Return the first password-policy violation, if any."""
    checks = (
        (
            len(password) <= MAX_PASSWORD_LENGTH,
            f"Password must not exceed {MAX_PASSWORD_LENGTH} characters.",
        ),
        (
            len(password) >= MIN_PASSWORD_LENGTH,
            "Password must contain at least 8 characters.",
        ),
        (
            re.search(r"[a-z]", password),
            "Password must contain at least one lowercase letter.",
        ),
        (
            re.search(r"[A-Z]", password),
            "Password must contain at least one uppercase letter.",
        ),
        (re.search(r"\d", password), "Password must contain at least one digit."),
        (
            re.search(r"[!@#$%^&*()\-_=+\[\]{};:,.<>?/]", password),
            "Password must contain at least one special character.",
        ),
    )
    for valid, message in checks:
        if not valid:
            return message
    return None


def validate_password_value(password: str) -> str:
    """Validate and return a password for use in Pydantic request schemas."""
    error = _password_policy_error(password)
    if error is not None:
        raise PasswordPolicyViolationError(error)
    return password


PasswordInput = Annotated[str, StringConstraints(max_length=MAX_PASSWORD_LENGTH)]


StrongPassword = Annotated[PasswordInput, AfterValidator(validate_password_value)]


def validate_password(password: str) -> None:
    """Raise when a password violates the shared credential-write policy."""
    validate_password_value(password)
