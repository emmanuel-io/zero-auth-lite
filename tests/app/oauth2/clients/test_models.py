"""Tests for OAuth2 client persistence invariants."""

from pathlib import Path
from typing import cast, TYPE_CHECKING
from uuid import UUID

import pytest
from app.db.base import Base
from app.db.models.oauth2_client import OAuth2ClientDB
from sqlalchemy import create_engine
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from tests.identifiers import deterministic_uuid


if TYPE_CHECKING:
    from sqlalchemy import Table


pytestmark = pytest.mark.integration


def _client(
    *, client_id: UUID, user_access: str, machine_access: str
) -> OAuth2ClientDB:
    """Build one OAuth2 client row with explicit organization-access modes."""
    return OAuth2ClientDB(
        client_id=client_id,
        client_secret=None,
        name="Client",
        grant_types=["authorization_code"],
        scopes=[],
        redirect_uris=["https://client.example/callback"],
        is_confidential=False,
        user_organization_access=user_access,
        machine_organization_access=machine_access,
    )


def test_oauth2_client_name_cannot_be_blank(tmp_path: Path) -> None:
    """Reject a persisted OAuth2 client without a meaningful display name."""
    engine = create_engine(f"sqlite:///{tmp_path / 'blank-client-name.db'}")
    try:
        with engine.connect() as connection:
            Base.metadata.create_all(
                connection,
                tables=cast("list[Table]", [OAuth2ClientDB.__table__]),
            )
            with Session(connection) as db_session:
                db_session.add(
                    OAuth2ClientDB(
                        client_id=deterministic_uuid("blank-name-client"),
                        client_secret=None,
                        name="   ",
                        grant_types=["authorization_code"],
                        scopes=[],
                        redirect_uris=["https://client.example/callback"],
                        is_confidential=False,
                    )
                )
                with pytest.raises(IntegrityError):
                    db_session.flush()
    finally:
        engine.dispose()


@pytest.mark.parametrize(
    "client_state",
    [(True, None), (False, "unexpected-secret")],
)
def test_oauth2_client_secret_matches_client_type(
    tmp_path: Path, client_state: tuple[bool, str | None]
) -> None:
    """Reject confidential clients without secrets and public clients with one."""
    is_confidential, client_secret = client_state
    engine = create_engine(f"sqlite:///{tmp_path / 'client-secret.db'}")
    try:
        with engine.connect() as connection:
            Base.metadata.create_all(
                connection,
                tables=cast("list[Table]", [OAuth2ClientDB.__table__]),
            )
            with Session(connection) as db_session:
                db_session.add(
                    OAuth2ClientDB(
                        client_id=deterministic_uuid("invalid-secret-client"),
                        client_secret=client_secret,
                        name="Client",
                        grant_types=["authorization_code"],
                        scopes=[],
                        redirect_uris=["https://client.example/callback"],
                        is_confidential=is_confidential,
                    )
                )
                with pytest.raises(IntegrityError, match="confidential_secret_valid"):
                    db_session.flush()
    finally:
        engine.dispose()


def test_oauth2_client_accepts_supported_organization_access_modes(
    tmp_path: Path,
) -> None:
    """Persist every supported user and machine organization-access mode."""
    engine = create_engine(f"sqlite:///{tmp_path / 'valid-client-access.db'}")
    try:
        with engine.connect() as connection:
            Base.metadata.create_all(
                connection,
                tables=cast("list[Table]", [OAuth2ClientDB.__table__]),
            )
            with Session(connection) as db_session:
                modes = (
                    ("unrestricted", "none"),
                    ("single", "single"),
                    ("selected", "selected"),
                    ("unrestricted", "unrestricted"),
                )
                db_session.add_all(
                    _client(
                        client_id=deterministic_uuid(f"client-{index}"),
                        user_access=user_access,
                        machine_access=machine_access,
                    )
                    for index, (user_access, machine_access) in enumerate(modes)
                )
                db_session.flush()
    finally:
        engine.dispose()


@pytest.mark.parametrize(
    ("user_access", "machine_access", "constraint_name"),
    [
        ("unknown", "none", "user_organization_access_valid"),
        ("unrestricted", "unknown", "machine_organization_access_valid"),
    ],
)
def test_oauth2_client_rejects_unknown_organization_access_modes(
    tmp_path: Path,
    user_access: str,
    machine_access: str,
    constraint_name: str,
) -> None:
    """Reject organization-access modes outside the supported vocabularies."""
    engine = create_engine(f"sqlite:///{tmp_path / f'{constraint_name}.db'}")
    try:
        with engine.connect() as connection:
            Base.metadata.create_all(
                connection,
                tables=cast("list[Table]", [OAuth2ClientDB.__table__]),
            )
            with Session(connection) as db_session:
                db_session.add(
                    _client(
                        client_id=deterministic_uuid("invalid-access-client"),
                        user_access=user_access,
                        machine_access=machine_access,
                    )
                )
                with pytest.raises(IntegrityError, match=constraint_name):
                    db_session.flush()
    finally:
        engine.dispose()
