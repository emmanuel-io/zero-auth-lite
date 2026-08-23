"""Integration tests for persisted authorization and token state constraints."""

import sqlite3
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config


PROJECT_ROOT = Path(__file__).parents[3]
NOW = "2026-08-18 12:00:00"


@pytest.fixture
def connection(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> sqlite3.Connection:
    """Return a SQLite connection migrated to the current canonical head."""
    database_path = tmp_path / "state-constraints.db"
    monkeypatch.setenv("ZA_DB_PATH", str(database_path))
    config = Config(str(PROJECT_ROOT / "alembic.ini"))
    config.set_main_option("script_location", str(PROJECT_ROOT / "alembic"))
    command.upgrade(config, "head")
    return sqlite3.connect(database_path)


def test_authorization_transaction_requires_a_complete_principal(
    connection: sqlite3.Connection,
) -> None:
    """Accept pending or bound transactions and reject partial principals."""
    statement = (
        "INSERT INTO oauth2_authorization_transaction "
        "(transaction_hash, response_type, client_id, redirect_uri, "
        "code_challenge, code_challenge_method, user_id, organization_id, "
        "expires_at, used_at) VALUES (?, 'code', 'client', 'https://client/cb', "
        "'challenge', 'S256', ?, ?, ?, ?)"
    )
    connection.execute(statement, ("pending", None, None, NOW, None))
    connection.execute(statement, ("bound", 1, 2, NOW, NOW))

    with pytest.raises(sqlite3.IntegrityError, match="principal_pair"):
        connection.execute(statement, ("partial", 1, None, NOW, None))
    with pytest.raises(sqlite3.IntegrityError, match="used_requires_principal"):
        connection.execute(statement, ("used-pending", None, None, NOW, NOW))


def test_device_authorization_enforces_decision_states(
    connection: sqlite3.Connection,
) -> None:
    """Accept the three decision states and reject contradictory decisions."""
    statement = (
        "INSERT INTO oauth2_device_authorization "
        "(device_code_hash, user_code_hash, client_id, scope, expires_at, "
        "interval_seconds, approved_at, denied_at, used_at, user_id, organization_id) "
        "VALUES (?, ?, 'client', '', ?, 5, ?, ?, ?, ?, ?)"
    )
    connection.execute(statement, ("d1", "u1", NOW, None, None, None, None, None))
    connection.execute(statement, ("d2", "u2", NOW, NOW, None, NOW, 1, 2))
    connection.execute(statement, ("d3", "u3", NOW, None, NOW, None, 1, 2))

    invalid_states = (
        ("d4", "u4", NOW, NOW, NOW, None, 1, 2),
        ("d5", "u5", NOW, None, NOW, NOW, 1, 2),
        ("d6", "u6", NOW, NOW, None, None, 1, None),
    )
    for values in invalid_states:
        with pytest.raises(sqlite3.IntegrityError, match="decision_state_valid"):
            connection.execute(statement, values)


def test_token_family_requires_complete_refresh_and_principal_pairs(
    connection: sqlite3.Connection,
) -> None:
    """Reject partial refresh-token and session-principal state."""
    session_statement = (
        "INSERT INTO oauth2_session "
        "(id, public_id, client_id, grant_type, scope, user_id, organization_id) "
        "VALUES (?, ?, 'client', 'authorization_code', '', ?, ?)"
    )
    connection.execute(session_statement, (1, 101, None, None))
    connection.execute(session_statement, (2, 102, 1, 2))
    connection.execute(session_statement, (3, 103, 1, 2))

    with pytest.raises(sqlite3.IntegrityError, match="principal_pair"):
        connection.execute(session_statement, (4, 104, 1, None))

    statement = (
        "INSERT INTO oauth2_token_pair "
        "(session_id, access_token_hash, access_jti, refresh_token_hash, "
        "access_expires_at, refresh_expires_at) VALUES (?, ?, ?, ?, ?, ?)"
    )
    connection.execute(statement, (1, "a1", "j1", None, NOW, None))
    connection.execute(statement, (2, "a2", "j2", "r2", NOW, NOW))

    with pytest.raises(sqlite3.IntegrityError, match="refresh_pair"):
        connection.execute(statement, (3, "a3", "j3", "r3", NOW, None))


def test_auth_token_requires_complete_event_derivation_metadata(
    connection: sqlite3.Connection,
) -> None:
    """Accept random and event-derived tokens but reject partial metadata."""
    statement = (
        "INSERT INTO user_auth_token "
        "(user_email_id, purpose, token_hash, source_event_id, "
        "source_event_occurred_at, derivation_key_id, expires_at, public_id) "
        "VALUES (1, 'verify_email', ?, ?, ?, ?, ?, ?)"
    )
    connection.execute(statement, ("t1", None, None, None, NOW, 1))
    connection.execute(statement, ("t2", "event", NOW, "key", NOW, 2))

    with pytest.raises(sqlite3.IntegrityError, match="event_derivation_fields"):
        connection.execute(statement, ("t3", "partial", None, "key", NOW, 3))
