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
        "VALUES (?, ?, 'client', ?, '', ?, ?)"
    )
    connection.execute(session_statement, (1, 101, "client_credentials", None, None))
    connection.execute(session_statement, (2, 102, "authorization_code", 1, 2))
    connection.execute(
        session_statement,
        (3, 103, "urn:ietf:params:oauth:grant-type:device_code", 1, 2),
    )

    invalid_principals = (
        (4, 104, "authorization_code", None, None),
        (5, 105, "authorization_code", 1, None),
        (6, 106, "authorization_code", None, 2),
        (7, 107, "urn:ietf:params:oauth:grant-type:device_code", None, None),
        (8, 108, "urn:ietf:params:oauth:grant-type:device_code", 1, None),
        (9, 109, "urn:ietf:params:oauth:grant-type:device_code", None, 2),
        (10, 110, "client_credentials", 1, None),
        (11, 111, "client_credentials", None, 2),
        (12, 112, "client_credentials", 1, 2),
    )
    for values in invalid_principals:
        with pytest.raises(sqlite3.IntegrityError, match="grant_principal_valid"):
            connection.execute(session_statement, values)
    with pytest.raises(
        sqlite3.IntegrityError,
        match=r"grant_(principal|type)_valid",
    ):
        connection.execute(
            session_statement,
            (13, 113, "unknown", None, None),
        )

    statement = (
        "INSERT INTO oauth2_token_state "
        "(session_id, access_token_hash, access_jti, refresh_token_hash, "
        "access_expires_at, refresh_expires_at) VALUES (?, ?, ?, ?, ?, ?)"
    )
    connection.execute(statement, (1, "a1", "j1", None, NOW, None))
    connection.execute(statement, (2, "a2", "j2", "r2", NOW, NOW))

    with pytest.raises(sqlite3.IntegrityError, match="refresh_pair"):
        connection.execute(statement, (3, "a3", "j3", "r3", NOW, None))


def test_workflow_token_requires_complete_event_derivation_metadata(
    connection: sqlite3.Connection,
) -> None:
    """Accept random and event-derived tokens but reject partial metadata."""
    statement = (
        "INSERT INTO user_workflow_token "
        "(user_email_id, purpose, token_hash, source_event_id, "
        "source_event_occurred_at, derivation_key_id, expires_at) "
        "VALUES (1, 'verify_email', ?, ?, ?, ?, ?)"
    )
    connection.execute(statement, ("t1", None, None, None, NOW))
    connection.execute(statement, ("t2", "event", NOW, "key", NOW))

    with pytest.raises(sqlite3.IntegrityError, match="event_derivation_fields"):
        connection.execute(statement, ("t3", "partial", None, "key", NOW))

    invalid_purpose_statement = statement.replace("'verify_email'", "'unknown'")
    with pytest.raises(sqlite3.IntegrityError, match="purpose_valid"):
        connection.execute(invalid_purpose_statement, ("t4", None, None, None, NOW))


def test_oauth2_authorization_values_use_supported_protocol_discriminators(
    connection: sqlite3.Connection,
) -> None:
    """Reject unsupported response types and PKCE methods."""
    transaction_statement = (
        "INSERT INTO oauth2_authorization_transaction "
        "(transaction_hash, response_type, client_id, redirect_uri, "
        "code_challenge, code_challenge_method, expires_at) "
        "VALUES (?, ?, 'client', 'https://client/cb', 'challenge', ?, ?)"
    )
    connection.execute(transaction_statement, ("valid", "code", "S256", NOW))
    with pytest.raises(sqlite3.IntegrityError, match="response_type_valid"):
        connection.execute(
            transaction_statement, ("invalid-response", "token", "S256", NOW)
        )
    with pytest.raises(sqlite3.IntegrityError, match="code_challenge_method_valid"):
        connection.execute(
            transaction_statement, ("invalid-method", "code", "plain", NOW)
        )

    code_statement = (
        "INSERT INTO oauth2_authorization_code "
        "(code_hash, client_id, redirect_uri, scope, code_challenge, "
        "code_challenge_method, expires_at, authenticated_at, user_id, "
        "organization_id) VALUES (?, 'client', 'https://client/cb', '', "
        "'challenge', ?, ?, ?, 1, 2)"
    )
    connection.execute(code_statement, ("valid-code", "S256", NOW, NOW))
    with pytest.raises(sqlite3.IntegrityError, match="code_challenge_method_valid"):
        connection.execute(code_statement, ("invalid-code", "plain", NOW, NOW))


def test_outbox_requires_coherent_delivery_state(
    connection: sqlite3.Connection,
) -> None:
    """Reject unsupported values and contradictory lease or terminal states."""
    statement = (
        "INSERT INTO notification_outbox "
        "(event_id, event_type, payload, occurred_at, available_at, attempt_count, "
        "claimed_at, claimed_by, processing_result, processed_at) "
        "VALUES (?, ?, '{}', ?, ?, ?, ?, ?, ?, ?)"
    )
    connection.execute(
        statement,
        ("event-pending", "auth.invite_created", NOW, NOW, 0, None, None, None, None),
    )
    connection.execute(
        statement,
        (
            "event-claimed",
            "auth.invite_created",
            NOW,
            NOW,
            1,
            NOW,
            "worker",
            None,
            None,
        ),
    )
    connection.execute(
        statement,
        (
            "event-terminal",
            "auth.invite_created",
            NOW,
            NOW,
            1,
            None,
            None,
            "failed_permanent",
            NOW,
        ),
    )
    with pytest.raises(sqlite3.IntegrityError, match="event_type_valid"):
        connection.execute(
            statement,
            ("event-unknown", "auth.unknown", NOW, NOW, 0, None, None, None, None),
        )
    with pytest.raises(sqlite3.IntegrityError, match="processing_result_valid"):
        connection.execute(
            statement,
            (
                "event-invalid-result",
                "auth.invite_created",
                NOW,
                NOW,
                0,
                None,
                None,
                "unknown",
                NOW,
            ),
        )
    invalid_states = (
        ("event-negative", -1, None, None, None, None, "attempt_count_nonnegative"),
        ("event-claim-time", 0, NOW, None, None, None, "claim_pair"),
        ("event-claim-owner", 0, None, "worker", None, None, "claim_pair"),
        ("event-result", 0, None, None, "delivered", None, "processing_pair"),
        ("event-processed", 0, None, None, None, NOW, "processing_pair"),
        (
            "event-terminal-claimed",
            0,
            NOW,
            "worker",
            "delivered",
            NOW,
            "processed_unclaimed",
        ),
    )
    for invalid_state in invalid_states:
        (
            event_id,
            attempts,
            claimed_at,
            claimed_by,
            result,
            processed_at,
            constraint,
        ) = invalid_state
        with pytest.raises(sqlite3.IntegrityError, match=constraint):
            connection.execute(
                statement,
                (
                    event_id,
                    "auth.invite_created",
                    NOW,
                    NOW,
                    attempts,
                    claimed_at,
                    claimed_by,
                    result,
                    processed_at,
                ),
            )


def test_oauth2_client_requires_valid_organization_access_modes(
    connection: sqlite3.Connection,
) -> None:
    """Accept supported access modes and reject unknown persisted policies."""
    statement = (
        "INSERT INTO oauth2_client "
        "(client_id, client_secret, name, grant_types, scopes, is_confidential, "
        "requires_consent, "
        "is_active, user_organization_access, machine_organization_access) "
        "VALUES (?, 'hash', 'Client', '[]', '[]', 1, 1, 1, ?, ?)"
    )
    valid_modes = (
        ("unrestricted", "none"),
        ("single", "single"),
        ("selected", "selected"),
        ("unrestricted", "unrestricted"),
    )
    for index, modes in enumerate(valid_modes):
        connection.execute(statement, (f"valid-{index}", *modes))

    with pytest.raises(sqlite3.IntegrityError, match="user_organization_access_valid"):
        connection.execute(statement, ("invalid-user", "unknown", "none"))
    with pytest.raises(
        sqlite3.IntegrityError, match="machine_organization_access_valid"
    ):
        connection.execute(statement, ("invalid-machine", "unrestricted", "unknown"))
