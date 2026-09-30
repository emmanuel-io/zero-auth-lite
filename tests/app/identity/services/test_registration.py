"""Tests for the canonical identity registration service."""

import sqlite3
from typing import get_type_hints
from uuid import UUID

import app.identity.services.registration as registration_module
import pytest
from app.core.errors.common import ObjectAlreadyExistsError
from app.db.errors import CheckViolationError
from app.identity.dtos import RegisteredUserDTO, RegistrationCreateDTO
from app.identity.services.registration import RegistrationService
from app.notifications.publisher import NotificationOutboxPublisher
from fastapi import FastAPI
from sqlalchemy.exc import IntegrityError


pytestmark = pytest.mark.unit
UUID_VERSION = 4


@pytest.mark.asyncio
async def test_registration_keeps_public_ids_typed_inside_the_service(
    app: FastAPI,
) -> None:
    """Leave public identifier formatting to the HTTP response boundary."""
    async with app.state.core_session_factory() as session:
        result = await RegistrationService(
            db_session=session,
            notification_publisher=NotificationOutboxPublisher(session),
            password_hasher=app.state.password_hasher,
        ).register(
            registration=RegistrationCreateDTO(
                email="typed-registration@example.com",
                password="S3cretPass1!",  # noqa: S106
                organization_name="Typed Registration",
            )
        )

    annotations = get_type_hints(RegisteredUserDTO)
    assert annotations["public_id"] is UUID
    assert annotations["organization_public_id"] is UUID
    assert result.public_id.version == UUID_VERSION
    assert result.organization_public_id.version == UUID_VERSION


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("sqlite_message", "expected_error"),
    [
        (
            "UNIQUE constraint failed: user_email.normalized_email",
            ObjectAlreadyExistsError,
        ),
        ("CHECK constraint failed: ck_user_email_current_state", CheckViolationError),
    ],
)
async def test_registration_classifies_integrity_errors_by_domain(
    app: FastAPI,
    monkeypatch: pytest.MonkeyPatch,
    sqlite_message: str,
    expected_error: type[ObjectAlreadyExistsError | CheckViolationError],
) -> None:
    """Reserve ALREADY_EXISTS for the known normalized-email collision."""

    async def fail_identity_creation(*args: object, **kwargs: object) -> None:
        del args, kwargs
        statement = "statement"
        raise IntegrityError(statement, {}, sqlite3.IntegrityError(sqlite_message))

    monkeypatch.setattr(
        registration_module,
        "create_user_identity",
        fail_identity_creation,
    )
    async with app.state.core_session_factory() as session:
        service = RegistrationService(
            db_session=session,
            notification_publisher=NotificationOutboxPublisher(session),
            password_hasher=app.state.password_hasher,
        )
        with pytest.raises(expected_error):
            await service.register(
                registration=RegistrationCreateDTO(
                    email="integrity-error@example.com",
                    password="S3cretPass1!",  # noqa: S106
                    organization_name="Integrity Error",
                )
            )
