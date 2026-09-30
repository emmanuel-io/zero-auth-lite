"""Tests for the canonical database migration baseline."""

import logging
import sqlite3
from pathlib import Path
from unittest.mock import patch

import pytest
from alembic import command
from alembic.config import Config
from alembic.script import ScriptDirectory
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
    assert _expected_migration_heads() == frozenset({"20260917_0001"})


def test_migration_logging_preserves_existing_application_loggers(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Keep host-process loggers enabled when Alembic configures its output."""
    logger = logging.getLogger("app.security.authentication")
    logger.disabled = False
    config = _alembic_config(
        database_path=tmp_path / "logging.db",
        monkeypatch=monkeypatch,
    )

    command.upgrade(config, "head")

    assert logger.disabled is False


@pytest.mark.unit
def test_checkout_migration_heads_are_loaded_once() -> None:
    """Avoid rescanning immutable Alembic scripts for every readiness probe."""
    _expected_migration_heads.cache_clear()
    with patch(
        "app.db.migrations.ScriptDirectory.from_config",
        wraps=ScriptDirectory.from_config,
    ) as from_config:
        first = _expected_migration_heads()
        second = _expected_migration_heads()

    assert first == second
    from_config.assert_called_once()


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
    """Create the canonical schema with its current names and identity fields."""
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
        oauth2_hash_indexes = {
            row[1]: bool(row[2])
            for table_name in (
                "oauth2_authorization_code",
                "oauth2_authorization_transaction",
                "oauth2_device_authorization",
            )
            for row in connection.execute(f'PRAGMA index_list("{table_name}")')
            if row[1].endswith("_hash")
        }
        authorization_transaction_client_indexes = {
            str(index_row[1]): (
                "oauth2_authorization_transaction",
                tuple(
                    str(column_row[2])
                    for column_row in connection.execute(
                        f'PRAGMA index_info("{index_row[1]}")'
                    )
                ),
            )
            for index_row in connection.execute(
                'PRAGMA index_list("oauth2_authorization_transaction")'
            )
            if index_row[1] == "ix_oauth2_authorization_transaction_client_id"
        }
        terminal_cleanup_indexes: dict[str, tuple[str, tuple[str, ...], bool, str]] = {}
        for table_name in (
            "oauth2_authorization_code",
            "oauth2_authorization_transaction",
            "oauth2_device_authorization",
        ):
            for index_row in connection.execute(f'PRAGMA index_list("{table_name}")'):
                index_name = str(index_row[1])
                if not index_name.endswith(("_used_id", "_denied_id")):
                    continue
                columns = tuple(
                    str(column_row[2])
                    for column_row in connection.execute(
                        f'PRAGMA index_info("{index_name}")'
                    )
                )
                index_sql = connection.execute(
                    "SELECT sql FROM sqlite_master WHERE type = 'index' AND name = ?",
                    (index_name,),
                ).fetchone()
                assert index_sql is not None
                where_clause = str(index_sql[0]).rsplit(" WHERE ", maxsplit=1)[1]
                terminal_cleanup_indexes[index_name] = (
                    table_name,
                    columns,
                    bool(index_row[4]),
                    where_clause,
                )

    assert revision == ("20260917_0001",)
    assert "oauth2_token_state" in tables
    assert "oauth2_token_pair" not in tables
    assert {"organization_id", "user_id", "role"} == membership_columns
    assert membership_primary_key == {"user_id"}
    assert membership_foreign_keys == {
        "organization_id": ("organization", "id", "RESTRICT"),
        "user_id": ("user", "id", "CASCADE"),
    }
    assert oauth2_hash_indexes == {
        "uq_oauth2_auth_code_hash": True,
        "uq_oauth2_auth_transaction_hash": True,
        "uq_oauth2_device_code_hash": True,
        "uq_oauth2_user_code_hash": True,
    }
    assert authorization_transaction_client_indexes == {
        "ix_oauth2_authorization_transaction_client_id": (
            "oauth2_authorization_transaction",
            ("client_id",),
        )
    }
    assert terminal_cleanup_indexes == {
        "ix_oauth2_authorization_code_used_id": (
            "oauth2_authorization_code",
            ("id",),
            True,
            "used_at IS NOT NULL",
        ),
        "ix_oauth2_authorization_transaction_used_id": (
            "oauth2_authorization_transaction",
            ("id",),
            True,
            "used_at IS NOT NULL",
        ),
        "ix_oauth2_device_authorization_used_id": (
            "oauth2_device_authorization",
            ("id",),
            True,
            "used_at IS NOT NULL",
        ),
        "ix_oauth2_device_authorization_denied_id": (
            "oauth2_device_authorization",
            ("id",),
            True,
            "denied_at IS NOT NULL",
        ),
    }
    assert user_columns == {
        "id",
        "public_id",
        "first_name",
        "last_name",
        "hashed_password",
        "is_active",
        "is_operator",
        "invitation_pending",
        "sessions_invalid_before",
        "created_at",
        "updated_at",
    }


@pytest.mark.integration
def test_terminal_cleanup_queries_use_partial_indexes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Use terminal indexes with live and terminal rows in each cleanup table."""
    database_path = tmp_path / "cleanup-query-plan.db"
    config = _alembic_config(database_path=database_path, monkeypatch=monkeypatch)
    command.upgrade(config, "head")

    with sqlite3.connect(database_path) as connection:
        connection.executemany(
            "INSERT INTO oauth2_authorization_code "
            "(code_hash, client_id, redirect_uri, scope, code_challenge, "
            "code_challenge_method, expires_at, authenticated_at, used_at, "
            "user_id, organization_id) VALUES (?, 'client', 'https://client.test', "
            "'read', 'challenge', 'S256', '2099-01-01', '2026-01-01', ?, 1, 1)",
            [
                (f"code-{row_id}", "2026-01-01" if row_id % 100 == 0 else None)
                for row_id in range(1, 1_001)
            ],
        )
        connection.executemany(
            "INSERT INTO oauth2_authorization_transaction "
            "(transaction_hash, response_type, client_id, redirect_uri, scope, "
            "code_challenge, code_challenge_method, expires_at, used_at, user_id, "
            "organization_id) VALUES (?, 'code', 'client', 'https://client.test', "
            "'read', 'challenge', 'S256', '2099-01-01', ?, ?, ?)",
            [
                (
                    f"transaction-{row_id}",
                    "2026-01-01" if row_id % 100 == 0 else None,
                    1 if row_id % 100 == 0 else None,
                    1 if row_id % 100 == 0 else None,
                )
                for row_id in range(1, 1_001)
            ],
        )
        connection.executemany(
            "INSERT INTO oauth2_device_authorization "
            "(device_code_hash, user_code_hash, client_id, scope, expires_at, "
            "interval_seconds, approved_at, denied_at, used_at, user_id, "
            "organization_id) VALUES (?, ?, 'client', 'read', '2099-01-01', 5, "
            "?, ?, ?, ?, ?)",
            [
                (
                    f"device-{row_id}",
                    f"user-{row_id}",
                    "2026-01-01" if row_id % 100 == 0 else None,
                    "2026-01-01" if row_id % 101 == 0 else None,
                    "2026-01-01" if row_id % 100 == 0 else None,
                    1 if row_id % 100 == 0 or row_id % 101 == 0 else None,
                    1 if row_id % 100 == 0 or row_id % 101 == 0 else None,
                )
                for row_id in range(1, 1_001)
            ],
        )
        connection.execute("ANALYZE")

        code_plan = " ".join(
            str(row[3])
            for row in connection.execute(
                "EXPLAIN QUERY PLAN SELECT id FROM ("
                "SELECT id FROM oauth2_authorization_code WHERE expires_at <= ? "
                "UNION SELECT id FROM oauth2_authorization_code "
                "WHERE used_at IS NOT NULL) ORDER BY id LIMIT 100",
                ("2026-09-16",),
            )
        )
        transaction_plan = " ".join(
            str(row[3])
            for row in connection.execute(
                "EXPLAIN QUERY PLAN SELECT id FROM ("
                "SELECT id FROM oauth2_authorization_transaction "
                "WHERE expires_at <= ? UNION SELECT id FROM "
                "oauth2_authorization_transaction WHERE used_at IS NOT NULL) "
                "ORDER BY id LIMIT 100",
                ("2026-09-16",),
            )
        )
        device_plan = " ".join(
            str(row[3])
            for row in connection.execute(
                "EXPLAIN QUERY PLAN SELECT id FROM ("
                "SELECT id FROM oauth2_device_authorization WHERE expires_at <= ? "
                "UNION SELECT id FROM oauth2_device_authorization "
                "WHERE used_at IS NOT NULL UNION SELECT id FROM "
                "oauth2_device_authorization WHERE denied_at IS NOT NULL) "
                "ORDER BY id LIMIT 100",
                ("2026-09-16",),
            )
        )

    assert "ix_oauth2_authorization_code_used_id" in code_plan
    assert "ix_oauth2_authorization_transaction_used_id" in transaction_plan
    assert "ix_oauth2_device_authorization_used_id" in device_plan
    assert "ix_oauth2_device_authorization_denied_id" in device_plan


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
