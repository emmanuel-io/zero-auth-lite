"""Move immutable OAuth2 token-family metadata to the session."""
# ruff: noqa: INP001

import sqlalchemy as sa
from alembic import op


revision: str = "20260821_0003"
down_revision: str | None = "20260818_0002"
branch_labels: str | None = None
depends_on: str | None = None


def upgrade() -> None:
    """Make the OAuth2 session own immutable authorization metadata."""
    op.add_column("oauth2_session", sa.Column("organization_id", sa.Integer()))
    op.add_column("oauth2_session", sa.Column("client_id", sa.String(length=32)))
    op.add_column("oauth2_session", sa.Column("grant_type", sa.String(length=64)))
    op.add_column("oauth2_session", sa.Column("scope", sa.String(length=512)))
    op.execute(
        sa.text(
            """
            UPDATE oauth2_session
            SET user_id = (
                    SELECT user_id FROM oauth2_token_pair
                    WHERE oauth2_token_pair.session_id = oauth2_session.id
                ),
                organization_id = (
                    SELECT organization_id FROM oauth2_token_pair
                    WHERE oauth2_token_pair.session_id = oauth2_session.id
                ),
                client_id = (
                    SELECT client_id FROM oauth2_token_pair
                    WHERE oauth2_token_pair.session_id = oauth2_session.id
                ),
                grant_type = (
                    SELECT grant_type FROM oauth2_token_pair
                    WHERE oauth2_token_pair.session_id = oauth2_session.id
                ),
                scope = (
                    SELECT scope FROM oauth2_token_pair
                    WHERE oauth2_token_pair.session_id = oauth2_session.id
                )
            WHERE EXISTS (
                SELECT 1 FROM oauth2_token_pair
                WHERE oauth2_token_pair.session_id = oauth2_session.id
            )
            """
        )
    )
    op.execute(
        sa.text(
            """
            DELETE FROM oauth2_session
            WHERE NOT EXISTS (
                SELECT 1 FROM oauth2_token_pair
                WHERE oauth2_token_pair.session_id = oauth2_session.id
            )
            """
        )
    )

    op.execute(
        sa.text(
            "CREATE TABLE oauth2_token_pair_migration AS "
            "SELECT * FROM oauth2_token_pair"
        )
    )
    op.execute(
        sa.text(
            "CREATE TABLE oauth2_refresh_history_migration AS "
            "SELECT * FROM oauth2_refresh_token_history"
        )
    )
    with op.batch_alter_table("oauth2_session") as batch_op:
        batch_op.alter_column("client_id", existing_type=sa.String(32), nullable=False)
        batch_op.alter_column("grant_type", existing_type=sa.String(64), nullable=False)
        batch_op.alter_column("scope", existing_type=sa.String(512), nullable=False)
        batch_op.create_foreign_key(
            op.f("fk_oauth2_session_client_id_oauth2_client"),
            "oauth2_client",
            ["client_id"],
            ["client_id"],
            ondelete="CASCADE",
        )
        batch_op.create_foreign_key(
            op.f("fk_oauth2_session_organization_id_organization"),
            "organization",
            ["organization_id"],
            ["id"],
            ondelete="CASCADE",
        )
        batch_op.create_check_constraint(
            op.f("ck_oauth2_session_principal_pair"),
            "(user_id IS NULL AND organization_id IS NULL) OR "
            "(user_id IS NOT NULL AND organization_id IS NOT NULL)",
        )
    op.execute(
        sa.text(
            "INSERT OR IGNORE INTO oauth2_token_pair "
            "SELECT * FROM oauth2_token_pair_migration"
        )
    )
    op.execute(
        sa.text(
            "INSERT OR IGNORE INTO oauth2_refresh_token_history "
            "SELECT * FROM oauth2_refresh_history_migration"
        )
    )

    op.create_index(
        op.f("ix_oauth2_session_client_id"), "oauth2_session", ["client_id"]
    )
    op.create_index(
        op.f("ix_oauth2_session_grant_type"), "oauth2_session", ["grant_type"]
    )
    op.create_index(
        "ix_oauth2_session_organization_created",
        "oauth2_session",
        ["organization_id", "created_at"],
    )
    op.create_index(
        "ix_oauth2_session_user_organization_created",
        "oauth2_session",
        ["user_id", "organization_id", "created_at"],
    )

    op.drop_index(
        op.f("ix_oauth2_token_pair_client_id"), table_name="oauth2_token_pair"
    )
    op.drop_index(
        op.f("ix_oauth2_token_pair_grant_type"), table_name="oauth2_token_pair"
    )
    op.drop_index(
        "ix_oauth2_token_pair_organization_created",
        table_name="oauth2_token_pair",
    )
    op.drop_index(
        "ix_oauth2_token_pair_user_organization_created",
        table_name="oauth2_token_pair",
    )
    with op.batch_alter_table("oauth2_token_pair") as batch_op:
        batch_op.drop_constraint(
            op.f("ck_oauth2_token_pair_principal_pair"), type_="check"
        )
        batch_op.drop_constraint(
            op.f("fk_oauth2_token_pair_client_id_oauth2_client"), type_="foreignkey"
        )
        batch_op.drop_constraint(
            op.f("fk_oauth2_token_pair_organization_id_organization"),
            type_="foreignkey",
        )
        batch_op.drop_constraint(
            op.f("fk_oauth2_token_pair_user_id_user"), type_="foreignkey"
        )
        batch_op.drop_column("client_id")
        batch_op.drop_column("grant_type")
        batch_op.drop_column("scope")
        batch_op.drop_column("user_id")
        batch_op.drop_column("organization_id")
    op.drop_table("oauth2_token_pair_migration")
    op.drop_table("oauth2_refresh_history_migration")


def downgrade() -> None:
    """Return immutable metadata to the current token-pair table."""
    op.execute(
        sa.text(
            """
            CREATE TABLE oauth2_token_family_metadata_migration AS
            SELECT id AS session_id, client_id, grant_type, scope,
                   user_id, organization_id
            FROM oauth2_session
            """
        )
    )
    op.execute(
        sa.text(
            "CREATE TABLE oauth2_token_pair_migration AS "
            "SELECT * FROM oauth2_token_pair"
        )
    )
    op.execute(
        sa.text(
            "CREATE TABLE oauth2_refresh_history_migration AS "
            "SELECT * FROM oauth2_refresh_token_history"
        )
    )
    op.drop_index(
        "ix_oauth2_session_user_organization_created", table_name="oauth2_session"
    )
    op.drop_index("ix_oauth2_session_organization_created", table_name="oauth2_session")
    op.drop_index(op.f("ix_oauth2_session_grant_type"), table_name="oauth2_session")
    op.drop_index(op.f("ix_oauth2_session_client_id"), table_name="oauth2_session")
    with op.batch_alter_table("oauth2_session") as batch_op:
        batch_op.drop_constraint(
            op.f("ck_oauth2_session_principal_pair"), type_="check"
        )
        batch_op.drop_constraint(
            op.f("fk_oauth2_session_organization_id_organization"), type_="foreignkey"
        )
        batch_op.drop_constraint(
            op.f("fk_oauth2_session_client_id_oauth2_client"), type_="foreignkey"
        )
        batch_op.drop_column("scope")
        batch_op.drop_column("grant_type")
        batch_op.drop_column("client_id")
        batch_op.drop_column("organization_id")
    op.execute(
        sa.text(
            "INSERT OR IGNORE INTO oauth2_token_pair "
            "SELECT * FROM oauth2_token_pair_migration"
        )
    )
    op.execute(
        sa.text(
            "INSERT OR IGNORE INTO oauth2_refresh_token_history "
            "SELECT * FROM oauth2_refresh_history_migration"
        )
    )

    op.add_column("oauth2_token_pair", sa.Column("client_id", sa.String(length=32)))
    op.add_column("oauth2_token_pair", sa.Column("grant_type", sa.String(length=64)))
    op.add_column("oauth2_token_pair", sa.Column("scope", sa.String(length=512)))
    op.add_column("oauth2_token_pair", sa.Column("user_id", sa.Integer()))
    op.add_column("oauth2_token_pair", sa.Column("organization_id", sa.Integer()))
    op.execute(
        sa.text(
            """
            UPDATE oauth2_token_pair
            SET client_id = (
                    SELECT client_id FROM oauth2_token_family_metadata_migration
                    WHERE session_id = oauth2_token_pair.session_id
                ),
                grant_type = (
                    SELECT grant_type FROM oauth2_token_family_metadata_migration
                    WHERE session_id = oauth2_token_pair.session_id
                ),
                scope = (
                    SELECT scope FROM oauth2_token_family_metadata_migration
                    WHERE session_id = oauth2_token_pair.session_id
                ),
                user_id = (
                    SELECT user_id FROM oauth2_token_family_metadata_migration
                    WHERE session_id = oauth2_token_pair.session_id
                ),
                organization_id = (
                    SELECT organization_id FROM oauth2_token_family_metadata_migration
                    WHERE session_id = oauth2_token_pair.session_id
                )
            """
        )
    )
    with op.batch_alter_table("oauth2_token_pair") as batch_op:
        batch_op.alter_column("grant_type", existing_type=sa.String(64), nullable=False)
        batch_op.alter_column("scope", existing_type=sa.String(512), nullable=False)
        batch_op.create_foreign_key(
            op.f("fk_oauth2_token_pair_client_id_oauth2_client"),
            "oauth2_client",
            ["client_id"],
            ["client_id"],
            ondelete="CASCADE",
        )
        batch_op.create_foreign_key(
            op.f("fk_oauth2_token_pair_organization_id_organization"),
            "organization",
            ["organization_id"],
            ["id"],
            ondelete="CASCADE",
        )
        batch_op.create_foreign_key(
            op.f("fk_oauth2_token_pair_user_id_user"),
            "user",
            ["user_id"],
            ["id"],
            ondelete="CASCADE",
        )
        batch_op.create_check_constraint(
            op.f("ck_oauth2_token_pair_principal_pair"),
            "(user_id IS NULL AND organization_id IS NULL) OR "
            "(user_id IS NOT NULL AND organization_id IS NOT NULL)",
        )
    op.create_index(
        op.f("ix_oauth2_token_pair_client_id"), "oauth2_token_pair", ["client_id"]
    )
    op.create_index(
        op.f("ix_oauth2_token_pair_grant_type"),
        "oauth2_token_pair",
        ["grant_type"],
    )
    op.create_index(
        "ix_oauth2_token_pair_organization_created",
        "oauth2_token_pair",
        ["organization_id", "created_at"],
    )
    op.create_index(
        "ix_oauth2_token_pair_user_organization_created",
        "oauth2_token_pair",
        ["user_id", "organization_id", "created_at"],
    )

    op.drop_table("oauth2_token_family_metadata_migration")
    op.drop_table("oauth2_token_pair_migration")
    op.drop_table("oauth2_refresh_history_migration")
