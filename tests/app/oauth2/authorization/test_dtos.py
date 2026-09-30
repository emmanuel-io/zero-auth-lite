"""Tests for strict OAuth2 authorization persistence DTOs."""

from datetime import datetime, timedelta, UTC

import pytest
from app.oauth2.authorization.dtos import (
    AuthorizationCodeCreateDTO,
    AuthorizationTransactionCreateDTO,
)
from pydantic import ValidationError

from tests.identifiers import deterministic_uuid


pytestmark = pytest.mark.unit


@pytest.mark.parametrize(
    ("dto", "values"),
    [
        (
            AuthorizationCodeCreateDTO,
            {
                "code_hash": "code-hash",
                "client_id": deterministic_uuid("client"),
                "redirect_uri": "https://client.example/callback",
                "scope": "openid",
                "nonce": "nonce",
                "code_challenge": "challenge",
                "code_challenge_method": "S256",
                "expires_at": datetime.now(UTC) + timedelta(minutes=5),
                "authenticated_at": datetime.now(UTC),
                "user_id": 1,
                "organization_id": 2,
            },
        ),
        (
            AuthorizationTransactionCreateDTO,
            {
                "transaction_hash": "transaction-hash",
                "response_type": "code",
                "client_id": deterministic_uuid("client"),
                "redirect_uri": "https://client.example/callback",
                "scope": "openid",
                "state": "state",
                "nonce": "nonce",
                "code_challenge": "challenge",
                "code_challenge_method": "S256",
                "expires_at": datetime.now(UTC) + timedelta(minutes=5),
            },
        ),
    ],
)
def test_authorization_create_dtos_reject_unknown_fields(
    dto: type[AuthorizationCodeCreateDTO | AuthorizationTransactionCreateDTO],
    values: dict[str, object],
) -> None:
    """Reject misspelled persistence data instead of silently dropping it."""
    with pytest.raises(ValidationError, match="unexpected"):
        dto.model_validate({**values, "unexpected": "value"})
