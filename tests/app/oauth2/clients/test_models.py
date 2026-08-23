"""Tests for OAuth2 client persistence invariants."""

from pathlib import Path

import pytest
from app.db.base import Base
from app.db.models.oauth2_client import OAuth2ClientDB
from sqlalchemy import create_engine
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session


pytestmark = pytest.mark.integration


def test_oauth2_client_name_cannot_be_blank(tmp_path: Path) -> None:
    """Reject a persisted OAuth2 client without a meaningful display name."""
    engine = create_engine(f"sqlite:///{tmp_path / 'blank-client-name.db'}")
    try:
        with engine.connect() as connection:
            Base.metadata.create_all(connection, tables=[OAuth2ClientDB.__table__])
            with Session(connection) as db_session:
                db_session.add(
                    OAuth2ClientDB(
                        client_id="blank-name-client",
                        client_secret=None,
                        name="   ",
                        grant_types=["authorization_code"],
                        scopes=[],
                        redirect_uris=["https://client.example/callback"],
                    )
                )
                with pytest.raises(IntegrityError):
                    db_session.flush()
    finally:
        engine.dispose()
