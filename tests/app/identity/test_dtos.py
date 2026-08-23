"""Tests for user service DTOs."""

from dataclasses import dataclass
from datetime import datetime, UTC

import pytest
from app.db.models.user import UserDB, UserEmailDB
from app.identity.organizations.dtos import OrganizationSelfReadDTO
from app.identity.users.dtos import (
    OrganizationUserCreateDTO,
    OrganizationUserReadDTO,
    to_organization_user_read_dto,
    to_user_read_dto,
    to_user_self_read_dto,
    UserSelfPatchDTO,
)
from app.identity.users.enums import OrganizationUserRole
from app.identity.users.specs import UserSpecs
from app.public_ids import PublicId
from pydantic import ValidationError


pytestmark = pytest.mark.unit


@dataclass
class UserReadSourceStub:
    """Test source object for user read mapping."""

    public_id: PublicId
    email: str
    first_name: str
    last_name: str
    is_active: bool
    is_operator: bool
    email_verified: bool
    created_at: datetime
    updated_at: datetime
    pending_email: str | None = None


def test_email_verification_belongs_to_the_email_record() -> None:
    """Keep address lifecycle state out of the stable user account row."""
    assert {"email", "pending_email", "email_verified"}.isdisjoint(
        UserDB.__table__.columns
    )
    assert "verified_at" in UserEmailDB.__table__.columns


def test_to_user_read_keeps_typed_organization_public_id() -> None:
    """Keep public organization IDs typed until the HTTP boundary."""
    now = datetime.now(UTC)
    user = UserReadSourceStub(
        public_id=PublicId(123),
        email="user@example.com",
        first_name="Test",
        last_name="User",
        is_active=True,
        is_operator=False,
        email_verified=True,
        created_at=now,
        updated_at=now,
    )

    dto = to_user_read_dto(user, 456, OrganizationUserRole.MEMBER)

    assert dto.organization_id == PublicId(456)


def test_to_user_read_allows_missing_organization() -> None:
    """Assert UserReadDTO supports users without organization data."""
    now = datetime.now(UTC)
    user = UserReadSourceStub(
        public_id=PublicId(123),
        email="user@example.com",
        first_name="Test",
        last_name="User",
        is_active=True,
        is_operator=False,
        email_verified=True,
        created_at=now,
        updated_at=now,
    )

    dto = to_user_read_dto(user, None, OrganizationUserRole.MEMBER)

    assert dto.organization_id is None


def test_to_organization_user_read_omits_global_only_fields() -> None:
    """Assert organization-scoped reads exclude operator and org identifiers."""
    now = datetime.now(UTC)
    user = UserReadSourceStub(
        public_id=PublicId(123),
        email="user@example.com",
        first_name="Test",
        last_name="User",
        is_active=True,
        is_operator=True,
        email_verified=True,
        created_at=now,
        updated_at=now,
    )

    dto = to_organization_user_read_dto(user, OrganizationUserRole.MEMBER)

    assert isinstance(dto, OrganizationUserReadDTO)
    assert dto.model_dump(by_alias=True).keys() == {
        "public_id",
        "email",
        "pending_email",
        "first_name",
        "last_name",
        "is_active",
        "role",
        "email_verified",
        "created_at",
        "updated_at",
    }


def test_to_user_self_read_embeds_organization_without_internal_identity_fields() -> (
    None
):
    """Expose useful self-service data without user or organization identifiers."""
    now = datetime.now(UTC)
    user = UserReadSourceStub(
        public_id=PublicId(123),
        email="user@example.com",
        first_name="Test",
        last_name="User",
        is_active=True,
        is_operator=True,
        email_verified=True,
        created_at=now,
        updated_at=now,
    )

    dto = to_user_self_read_dto(
        user,
        OrganizationSelfReadDTO(name="Example Organization"),
        OrganizationUserRole.ADMIN,
    )
    payload = dto.model_dump(mode="json")

    assert payload["organization"] == {"name": "Example Organization"}
    assert {"id", "user_id", "organization_id", "is_operator"}.isdisjoint(payload)


def test_user_write_schemas_reject_names_over_persistence_limits() -> None:
    """Reject profile names that the relational model cannot persist."""
    with pytest.raises(ValidationError):
        OrganizationUserCreateDTO(
            email="user@example.com",
            first_name="x" * (UserSpecs.FIRST_NAME_LENGTH_MAX + 1),
        )
    with pytest.raises(ValidationError):
        UserSelfPatchDTO(
            last_name="x" * (UserSpecs.LAST_NAME_LENGTH_MAX + 1),
        )
