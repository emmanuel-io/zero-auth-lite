"""Tests for the application password policy."""

import pytest
from app.api.v1.auth.schemas import PasswordTokenRequest, RegisterRequest
from app.api.v1.browser_sessions.schemas import LoginRequest
from app.identity.users.dtos import OrganizationUserCreateDTO, UserPasswordChangeDTO
from app.password.errors import PasswordPolicyViolationError
from app.password.validation import MAX_PASSWORD_LENGTH, validate_password
from pydantic import BaseModel, ValidationError


pytestmark = pytest.mark.unit

TEST_PASSWORD = "S3cretPass1!"  # noqa: S105


@pytest.mark.parametrize(
    "password",
    [
        "Short1!",
        "NOLOWERCASE1!",
        "nouppercase1!",
        "NoDigit!",
        "NoSpecial1",
    ],
)
@pytest.mark.negative
def test_validate_password_rejects_weak_passwords(password: str) -> None:
    """Assert weak passwords fail validation."""
    with pytest.raises(PasswordPolicyViolationError):
        validate_password(password)


def test_validate_password_accepts_strong_password() -> None:
    """Assert strong passwords pass validation."""
    validate_password(TEST_PASSWORD)


@pytest.mark.negative
def test_validate_password_rejects_oversized_password() -> None:
    """Assert bootstrap password validation enforces the shared input limit."""
    with pytest.raises(PasswordPolicyViolationError):
        validate_password("A1!a" * (MAX_PASSWORD_LENGTH // 4 + 1))


@pytest.mark.parametrize(
    ("schema", "payload"),
    [
        (
            RegisterRequest,
            {"email": "user@example.test", "password": "weak"},
        ),
        (
            OrganizationUserCreateDTO,
            {"email": "user@example.test", "password": "weak"},
        ),
        (
            UserPasswordChangeDTO,
            {"current_password": TEST_PASSWORD, "new_password": "weak"},
        ),
        (
            PasswordTokenRequest,
            {"token": "a" * 16, "password": "weak"},
        ),
    ],
)
@pytest.mark.negative
def test_credential_write_schemas_apply_password_policy(
    schema: type[BaseModel], payload: dict[str, str]
) -> None:
    """Assert every public credential-write schema rejects weak passwords."""
    with pytest.raises(ValidationError, match="at least 8 characters"):
        schema(**payload)


@pytest.mark.parametrize(
    ("schema", "payload"),
    [
        (
            LoginRequest,
            {"username": "user@example.test", "password": "x"},
        ),
        (
            RegisterRequest,
            {
                "email": "user@example.test",
                "password": "x",
                "organization_name": "Example",
            },
        ),
        (
            OrganizationUserCreateDTO,
            {"email": "user@example.test", "password": "x"},
        ),
        (
            UserPasswordChangeDTO,
            {"current_password": "x", "new_password": TEST_PASSWORD},
        ),
        (
            PasswordTokenRequest,
            {"token": "a" * 16, "password": "x"},
        ),
    ],
)
@pytest.mark.negative
def test_password_inputs_reject_oversized_values(
    schema: type[BaseModel], payload: dict[str, str]
) -> None:
    """Assert raw and policy-validated password inputs share one upper bound."""
    payload["password" if "password" in payload else "current_password"] = "x" * (
        MAX_PASSWORD_LENGTH + 1
    )
    with pytest.raises(ValidationError, match="at most 1024 characters"):
        schema(**payload)
