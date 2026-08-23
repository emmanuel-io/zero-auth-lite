"""Tests for the canonical initial database migration."""

import sqlite3
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from app.db.migrations import (
    _expected_migration_heads,
    _require_current_migration_heads,
)


PROJECT_ROOT = Path(__file__).parents[3]


def _alembic_config(*, database_path: Path, monkeypatch: pytest.MonkeyPatch) -> Config:
    """Configure Alembic against one isolated SQLite database."""
    monkeypatch.setenv("ZA_DB_PATH", str(database_path))
    config = Config(str(PROJECT_ROOT / "alembic.ini"))
    config.set_main_option("script_location", str(PROJECT_ROOT / "alembic"))
    return config


@pytest.mark.unit
def test_checkout_exposes_the_canonical_alembic_head() -> None:
    """Resolve the canonical migration head shipped by the checkout."""
    assert _expected_migration_heads() == frozenset({"20260821_0003"})


@pytest.mark.unit
def test_startup_accepts_the_current_database_revision() -> None:
    """Accept a database only when its recorded head matches the checkout."""
    heads = frozenset({"current-head"})
    _require_current_migration_heads(current_heads=heads, expected_heads=heads)


@pytest.mark.unit
def test_startup_rejects_an_uninitialized_database() -> None:
    """Reject an empty database before its first domain query."""
    with pytest.raises(RuntimeError, match="not initialized with Alembic"):
        _require_current_migration_heads(
            current_heads=frozenset(),
            expected_heads=frozenset({"current-head"}),
        )


@pytest.mark.unit
def test_startup_rejects_an_outdated_database() -> None:
    """Reject a database whose recorded revision differs from the checkout."""
    with pytest.raises(RuntimeError, match="current: old-head; expected: current-head"):
        _require_current_migration_heads(
            current_heads=frozenset({"old-head"}),
            expected_heads=frozenset({"current-head"}),
        )


@pytest.mark.integration
def test_initial_migration_creates_the_canonical_schema(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Create the canonical schema with membership-scoped roles."""
    database_path = tmp_path / "canonical-schema.db"
    config = _alembic_config(database_path=database_path, monkeypatch=monkeypatch)
    command.upgrade(config, "head")

    with sqlite3.connect(database_path) as connection:
        revision = connection.execute(
            "SELECT version_num FROM alembic_version"
        ).fetchone()
        tables = {
            row[0]
            for row in connection.execute(
                "SELECT name FROM sqlite_master "
                "WHERE type = 'table' AND name NOT LIKE 'sqlite_%' "
                "AND name != 'alembic_version'"
            )
        }
        user_columns = {
            row[1] for row in connection.execute('PRAGMA table_info("user")')
        }
        membership_columns = {
            row[1]
            for row in connection.execute(
                'PRAGMA table_info("organization_membership")'
            )
        }
        membership_primary_key = {
            row[1]
            for row in connection.execute(
                'PRAGMA table_info("organization_membership")'
            )
            if row[5]
        }
        membership_foreign_keys = {
            row[3]: (row[2], row[4], row[6])
            for row in connection.execute(
                'PRAGMA foreign_key_list("organization_membership")'
            )
        }
        membership_schema = connection.execute(
            "SELECT sql FROM sqlite_master "
            "WHERE type = 'table' AND name = 'organization_membership'"
        ).fetchone()

    assert revision == ("20260821_0003",)
    assert "organization_membership" in tables
    assert {"organization_id", "user_id", "role"} == membership_columns
    assert membership_primary_key == {"user_id"}
    assert membership_foreign_keys == {
        "organization_id": ("organization", "id", "RESTRICT"),
        "user_id": ("user", "id", "CASCADE"),
    }
    assert user_columns == {
        "id",
        "public_id",
        "first_name",
        "last_name",
        "hashed_password",
        "is_active",
        "is_operator",
        "sessions_invalid_before",
        "created_at",
        "updated_at",
    }
    assert membership_schema is not None
    assert "member" in membership_schema[0]
    assert "admin" in membership_schema[0]


@pytest.mark.integration
def test_initial_migration_downgrades_to_an_empty_schema(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Drop every canonical table when downgrading the initial revision."""
    database_path = tmp_path / "canonical-downgrade.db"
    config = _alembic_config(database_path=database_path, monkeypatch=monkeypatch)
    command.upgrade(config, "head")
    command.downgrade(config, "base")

    with sqlite3.connect(database_path) as connection:
        tables = {
            row[0]
            for row in connection.execute(
                "SELECT name FROM sqlite_master "
                "WHERE type = 'table' AND name NOT LIKE 'sqlite_%' "
                "AND name != 'alembic_version'"
            )
        }

    assert tables == set()


@pytest.mark.integration
def test_token_family_metadata_migration_backfills_and_downgrades(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Move retained family metadata and discard pre-existing orphan sessions."""
    database_path = tmp_path / "token-family-metadata.db"
    config = _alembic_config(database_path=database_path, monkeypatch=monkeypatch)
    command.upgrade(config, "20260818_0002")
    with sqlite3.connect(database_path) as connection:
        connection.execute(
            "INSERT INTO oauth2_client "
            "(client_id, name, grant_types, scopes, is_confidential, "
            "requires_consent, is_active) VALUES (?, ?, ?, ?, ?, ?, ?)",
            ("client", "Client", '["authorization_code"]', '["openid"]', 0, 0, 1),
        )
        connection.execute(
            "INSERT INTO organization (id, name, public_id) VALUES (1, 'Org', 11)"
        )
        connection.execute(
            "INSERT INTO user (id, first_name, last_name, hashed_password, "
            "is_active, is_operator, public_id) "
            "VALUES (1, 'Test', 'User', 'hash', 1, 0, 12)"
        )
        connection.execute(
            "INSERT INTO oauth2_session (id, public_id, user_id) VALUES (1, 21, 1)"
        )
        connection.execute(
            "INSERT INTO oauth2_session (id, public_id, user_id) VALUES (2, 22, 1)"
        )
        connection.execute(
            "INSERT INTO oauth2_token_pair "
            "(session_id, access_token_hash, access_jti, refresh_token_hash, "
            "grant_type, client_id, scope, access_expires_at, refresh_expires_at, "
            "user_id, organization_id) VALUES "
            "(1, 'access', 'jti', 'refresh', 'authorization_code', 'client', "
            "'openid', '2030-01-01', '2030-02-01', 1, 1)"
        )
        connection.commit()

    command.upgrade(config, "head")
    with sqlite3.connect(database_path) as connection:
        session = connection.execute(
            "SELECT client_id, grant_type, scope, user_id, organization_id "
            "FROM oauth2_session WHERE id = 1"
        ).fetchone()
        orphan = connection.execute(
            "SELECT id FROM oauth2_session WHERE id = 2"
        ).fetchone()
        pair_columns = {
            row[1]
            for row in connection.execute('PRAGMA table_info("oauth2_token_pair")')
        }
        retained_pair = connection.execute(
            "SELECT session_id FROM oauth2_token_pair WHERE session_id = 1"
        ).fetchone()
    assert session == ("client", "authorization_code", "openid", 1, 1)
    assert orphan is None
    assert retained_pair == (1,)
    assert {
        "client_id",
        "grant_type",
        "scope",
        "user_id",
        "organization_id",
    }.isdisjoint(pair_columns)

    command.downgrade(config, "20260818_0002")
    with sqlite3.connect(database_path) as connection:
        restored = connection.execute(
            "SELECT client_id, grant_type, scope, user_id, organization_id "
            "FROM oauth2_token_pair WHERE session_id = 1"
        ).fetchone()
    assert restored == ("client", "authorization_code", "openid", 1, 1)


@pytest.mark.integration
def test_migrations_match_canonical_orm_metadata(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Reject ORM changes without a corresponding migration."""
    config = _alembic_config(
        database_path=tmp_path / "migration-drift.db",
        monkeypatch=monkeypatch,
    )
    command.upgrade(config, "head")
    command.check(config)
