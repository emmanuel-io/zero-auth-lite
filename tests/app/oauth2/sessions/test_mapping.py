"""Tests for OAuth2 session DTOs, mapping, and HTTP schema naming."""

from datetime import datetime, UTC
from typing import Any

import pytest
from app.api.v1.organization.oauth2_sessions.schemas import (
    OrganizationOAuth2SessionResponse,
)
from app.db.models.oauth2_session import OAuth2SessionDB
from app.oauth2.grants.types import OAuth2SessionGrantType
from app.oauth2.organization_oauth2_sessions.dtos import OrganizationOAuth2SessionDTO
from app.oauth2.sessions.dtos import OAuth2SessionReadDTO
from app.oauth2.sessions.mapping import to_oauth2_session_dto

from tests.identifiers import (
    deterministic_uuid,
    format_public_id as format_oauth2_session_id,
    format_public_id as format_organization_id,
    format_public_id as format_user_id,
    PublicId,
)


pytestmark = pytest.mark.unit


def test_oauth2_session_mapping_converts_persisted_grant_type() -> None:
    """Expose stored session grants through the narrower domain vocabulary."""

    now = datetime.now(UTC)
    row = OAuth2SessionDB(
        id=1,
        public_id=1,
        client_id=deterministic_uuid("client"),
        grant_type="authorization_code",
        scope="openid",
        user_id=1,
        organization_id=1,
        created_at=now,
        updated_at=now,
    )

    dto = to_oauth2_session_dto(row)

    assert dto.grant_type is OAuth2SessionGrantType.AUTHORIZATION_CODE


def test_oauth2_session_api_schema_hides_the_persistence_distinction() -> None:
    """Keep persistence names out of the organization HTTP contract."""
    properties = OrganizationOAuth2SessionResponse.model_json_schema(
        mode="serialization"
    )["properties"]

    assert "id" in properties
    assert "scopes" in properties
    assert "session_id" not in properties
    assert "scope" not in properties
    assert "public_id" not in properties
    assert "session_ended_at" not in properties


def test_oauth2_session_http_schema_serializes_typed_public_ids() -> None:
    """Keep identifier prefixes and aliases at the versioned HTTP boundary."""
    now = datetime.now(UTC)
    dto = OrganizationOAuth2SessionDTO(
        public_id=PublicId(1),
        client_id=deterministic_uuid("client"),
        grant_type=OAuth2SessionGrantType.AUTHORIZATION_CODE,
        scopes=["openid"],
        user_public_id=PublicId(2),
        organization_public_id=PublicId(3),
        active=True,
        access_expires_at=now,
        refresh_expires_at=None,
        created_at=now,
        updated_at=now,
    )

    payload = OrganizationOAuth2SessionResponse(
        id=format_oauth2_session_id(dto.public_id),
        client_id=dto.client_id,
        grant_type=dto.grant_type,
        scopes=dto.scopes,
        user_public_id=dto.user_public_id,
        organization_public_id=dto.organization_public_id,
        active=dto.active,
        access_expires_at=dto.access_expires_at,
        refresh_expires_at=dto.refresh_expires_at,
        created_at=dto.created_at,
        updated_at=dto.updated_at,
    ).model_dump(mode="json", by_alias=True)

    assert payload["id"] == format_oauth2_session_id(PublicId(1))
    assert payload["scopes"] == ["openid"]
    assert payload["user_id"] == format_user_id(PublicId(2))
    assert payload["organization_id"] == format_organization_id(PublicId(3))


@pytest.mark.parametrize("missing_field", ["created_at", "updated_at"])
def test_oauth2_session_read_requires_persisted_timestamps(missing_field: str) -> None:
    """Do not invent creation or update times for a stored OAuth2 session."""
    now = datetime.now(UTC)
    values: dict[str, Any] = {
        "id": 1,
        "public_id": PublicId(1),
        "client_id": deterministic_uuid("client"),
        "grant_type": OAuth2SessionGrantType.AUTHORIZATION_CODE,
        "scope": "openid",
        "user_id": 1,
        "organization_id": 1,
        "created_at": now,
        "updated_at": now,
    }
    values.pop(missing_field)

    with pytest.raises(TypeError):
        OAuth2SessionReadDTO(**values)
