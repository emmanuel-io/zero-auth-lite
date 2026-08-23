"""Unit tests for versioned registration request schemas."""

import pytest
from app.api.v1.auth.schemas import RegisterRequest
from app.identity.users.specs import UserSpecs
from pydantic import ValidationError


pytestmark = pytest.mark.unit


def test_register_request_rejects_blank_organization_name() -> None:
    """Require registration to create a named organization."""
    with pytest.raises(ValidationError):
        RegisterRequest(
            email="new-user@zero-auth-lite.dev",
            password="ValidPass1!",  # noqa: S106
            organization_name="   ",
        )


def test_register_request_rejects_overlong_user_name() -> None:
    """Keep registration profile names within persistence limits."""
    with pytest.raises(ValidationError):
        RegisterRequest(
            email="new-user@zero-auth-lite.dev",
            password="ValidPass1!",  # noqa: S106
            first_name="x" * (UserSpecs.FIRST_NAME_LENGTH_MAX + 1),
            organization_name="New Organization",
        )
