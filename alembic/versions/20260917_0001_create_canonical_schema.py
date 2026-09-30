"""Create the canonical UUIDv4 database schema."""

# ruff: noqa: E501, INP001, PLR0915

import sqlalchemy as sa
from alembic import op


revision: str = "20260917_0001"
down_revision: str | None = None
branch_labels: str | None = None
depends_on: str | None = None


def upgrade() -> None:
    """Create the complete canonical schema."""
    op.create_table(
        "notification_outbox",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("event_id", sa.String(length=32), nullable=False),
        sa.Column("event_type", sa.String(length=96), nullable=False),
        sa.Column("correlation_id", sa.String(length=32), nullable=True),
        sa.Column("payload", sa.JSON(), nullable=False),
        sa.Column("occurred_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("available_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("attempt_count", sa.Integer(), nullable=False),
        sa.Column("claimed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("claimed_by", sa.String(length=32), nullable=True),
        sa.Column("last_error", sa.Text(), nullable=True),
        sa.Column("processing_result", sa.String(length=28), nullable=True),
        sa.Column("processed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("(CURRENT_TIMESTAMP)"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("(CURRENT_TIMESTAMP)"),
            nullable=False,
        ),
        sa.CheckConstraint(
            "event_type IN ('auth.password_reset_requested', 'auth.account_verification_requested', 'auth.email_change_requested', 'auth.invite_created')",
            name=op.f("ck_notification_outbox_event_type_valid"),
        ),
        sa.CheckConstraint(
            "processing_result IS NULL OR processing_result IN ('delivered', 'discarded_email_disabled', 'discarded_target_unavailable', 'failed_permanent')",
            name=op.f("ck_notification_outbox_processing_result_valid"),
        ),
        sa.CheckConstraint(
            "(claimed_at IS NULL AND claimed_by IS NULL) OR (claimed_at IS NOT NULL AND claimed_by IS NOT NULL)",
            name=op.f("ck_notification_outbox_claim_pair"),
        ),
        sa.CheckConstraint(
            "(processed_at IS NULL AND processing_result IS NULL) OR (processed_at IS NOT NULL AND processing_result IS NOT NULL)",
            name=op.f("ck_notification_outbox_processing_pair"),
        ),
        sa.CheckConstraint(
            "attempt_count >= 0",
            name=op.f("ck_notification_outbox_attempt_count_nonnegative"),
        ),
        sa.CheckConstraint(
            "processed_at IS NULL OR (claimed_at IS NULL AND claimed_by IS NULL)",
            name=op.f("ck_notification_outbox_processed_unclaimed"),
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_notification_outbox")),
        sa.UniqueConstraint("event_id", name=op.f("uq_notification_outbox_event_id")),
    )
    op.create_index(
        op.f("ix_notification_outbox_available_at"),
        "notification_outbox",
        ["available_at"],
        unique=False,
    )
    op.create_index(
        op.f("ix_notification_outbox_claimed_at"),
        "notification_outbox",
        ["claimed_at"],
        unique=False,
    )
    op.create_index(
        op.f("ix_notification_outbox_event_type"),
        "notification_outbox",
        ["event_type"],
        unique=False,
    )
    op.create_index(
        op.f("ix_notification_outbox_processed_at"),
        "notification_outbox",
        ["processed_at"],
        unique=False,
    )
    op.create_table(
        "oauth2_client",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("client_id", sa.Uuid(), nullable=False),
        sa.Column("client_secret", sa.String(length=128), nullable=True),
        sa.Column("name", sa.String(length=100), nullable=False),
        sa.Column("grant_types", sa.JSON(), nullable=False),
        sa.Column("scopes", sa.JSON(), nullable=False),
        sa.Column("redirect_uris", sa.JSON(), nullable=True),
        sa.Column("is_confidential", sa.Boolean(), nullable=False),
        sa.Column("requires_consent", sa.Boolean(), nullable=False),
        sa.Column("is_active", sa.Boolean(), nullable=False),
        sa.Column(
            "user_organization_access",
            sa.String(length=12),
            server_default="unrestricted",
            nullable=False,
        ),
        sa.Column(
            "machine_organization_access",
            sa.String(length=12),
            server_default="none",
            nullable=False,
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("(CURRENT_TIMESTAMP)"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("(CURRENT_TIMESTAMP)"),
            nullable=False,
        ),
        sa.CheckConstraint(
            "machine_organization_access IN ('none', 'single', 'selected', 'unrestricted')",
            name=op.f("ck_oauth2_client_machine_organization_access_valid"),
        ),
        sa.CheckConstraint(
            "user_organization_access IN ('unrestricted', 'single', 'selected')",
            name=op.f("ck_oauth2_client_user_organization_access_valid"),
        ),
        sa.CheckConstraint(
            "(is_confidential = 1 AND client_secret IS NOT NULL) OR (is_confidential = 0 AND client_secret IS NULL)",
            name=op.f("ck_oauth2_client_confidential_secret_valid"),
        ),
        sa.CheckConstraint(
            "length(trim(name)) > 0", name=op.f("ck_oauth2_client_name_not_blank")
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_oauth2_client")),
        sa.UniqueConstraint("client_id", name=op.f("uq_oauth2_client_client_id")),
    )
    op.create_table(
        "organization",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("name", sa.String(length=32), nullable=False),
        sa.Column("public_id", sa.Uuid(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("(CURRENT_TIMESTAMP)"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("(CURRENT_TIMESTAMP)"),
            nullable=False,
        ),
        sa.CheckConstraint(
            "length(trim(name)) > 0", name=op.f("ck_organization_name_not_blank")
        ),
        sa.CheckConstraint(
            "instr(name, char(13)) = 0 AND instr(name, char(10)) = 0",
            name=op.f("ck_organization_name_no_line_breaks"),
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_organization")),
    )
    op.create_index(
        op.f("ix_organization_name"), "organization", ["name"], unique=False
    )
    op.create_index(
        op.f("ix_organization_public_id"), "organization", ["public_id"], unique=True
    )
    op.create_table(
        "user",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("first_name", sa.String(length=64), nullable=False),
        sa.Column("last_name", sa.String(length=64), nullable=False),
        sa.Column("hashed_password", sa.String(), nullable=False),
        sa.Column("is_active", sa.Boolean(), nullable=False),
        sa.Column("is_operator", sa.Boolean(), nullable=False),
        sa.Column("invitation_pending", sa.Boolean(), nullable=False),
        sa.Column("sessions_invalid_before", sa.DateTime(timezone=True), nullable=True),
        sa.Column("public_id", sa.Uuid(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("(CURRENT_TIMESTAMP)"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("(CURRENT_TIMESTAMP)"),
            nullable=False,
        ),
        sa.CheckConstraint(
            "instr(first_name, char(13)) = 0 AND instr(first_name, char(10)) = 0",
            name=op.f("ck_user_first_name_no_line_breaks"),
        ),
        sa.CheckConstraint(
            "instr(last_name, char(13)) = 0 AND instr(last_name, char(10)) = 0",
            name=op.f("ck_user_last_name_no_line_breaks"),
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_user")),
    )
    op.create_index(op.f("ix_user_public_id"), "user", ["public_id"], unique=True)
    op.create_table(
        "browser_session",
        sa.Column("id", sa.String(length=64), nullable=False),
        sa.Column("public_id", sa.Uuid(), nullable=False),
        sa.Column("csrf", sa.String(length=43), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("absolute_expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revoked_reason", sa.String(length=64), nullable=True),
        sa.Column("ip_hash", sa.String(length=64), nullable=True),
        sa.Column("user_agent_hash", sa.String(length=64), nullable=True),
        sa.Column("user_id", sa.Integer(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("(CURRENT_TIMESTAMP)"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("(CURRENT_TIMESTAMP)"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["user_id"],
            ["user.id"],
            name=op.f("fk_browser_session_user_id_user"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_browser_session")),
    )
    op.create_index(
        op.f("ix_browser_session_absolute_expires_at"),
        "browser_session",
        ["absolute_expires_at"],
        unique=False,
    )
    op.create_index(
        op.f("ix_browser_session_expires_at"),
        "browser_session",
        ["expires_at"],
        unique=False,
    )
    op.create_index(
        op.f("ix_browser_session_public_id"),
        "browser_session",
        ["public_id"],
        unique=True,
    )
    op.create_index(
        op.f("ix_browser_session_revoked_at"),
        "browser_session",
        ["revoked_at"],
        unique=False,
    )
    op.create_index(
        "ix_browser_session_user_expires",
        "browser_session",
        ["user_id", "expires_at"],
        unique=False,
    )
    op.create_index(
        "ix_browser_session_user_last_seen",
        "browser_session",
        ["user_id", "last_seen_at"],
        unique=False,
    )
    op.create_table(
        "oauth2_authorization_code",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("code_hash", sa.String(length=64), nullable=False),
        sa.Column("client_id", sa.Uuid(), nullable=False),
        sa.Column("redirect_uri", sa.String(length=256), nullable=False),
        sa.Column("scope", sa.String(length=512), nullable=False),
        sa.Column("nonce", sa.String(length=512), nullable=True),
        sa.Column("code_challenge", sa.String(length=43), nullable=False),
        sa.Column("code_challenge_method", sa.String(length=10), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("authenticated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("used_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("user_id", sa.Integer(), nullable=False),
        sa.Column("organization_id", sa.Integer(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("(CURRENT_TIMESTAMP)"),
            nullable=False,
        ),
        sa.CheckConstraint(
            "code_challenge_method = 'S256'",
            name=op.f("ck_oauth2_authorization_code_code_challenge_method_valid"),
        ),
        sa.ForeignKeyConstraint(
            ["client_id"],
            ["oauth2_client.client_id"],
            name=op.f("fk_oauth2_authorization_code_client_id_oauth2_client"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["organization_id"],
            ["organization.id"],
            name=op.f("fk_oauth2_authorization_code_organization_id_organization"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["user_id"],
            ["user.id"],
            name=op.f("fk_oauth2_authorization_code_user_id_user"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_oauth2_authorization_code")),
    )
    op.create_index(
        "ix_oauth2_auth_code_client_expires",
        "oauth2_authorization_code",
        ["client_id", "expires_at"],
        unique=False,
    )
    op.create_index(
        "uq_oauth2_auth_code_hash",
        "oauth2_authorization_code",
        ["code_hash"],
        unique=True,
    )
    op.create_index(
        op.f("ix_oauth2_authorization_code_expires_at"),
        "oauth2_authorization_code",
        ["expires_at"],
        unique=False,
    )
    op.create_index(
        op.f("ix_oauth2_authorization_code_organization_id"),
        "oauth2_authorization_code",
        ["organization_id"],
        unique=False,
    )
    op.create_index(
        op.f("ix_oauth2_authorization_code_user_id"),
        "oauth2_authorization_code",
        ["user_id"],
        unique=False,
    )
    op.create_table(
        "oauth2_authorization_transaction",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("transaction_hash", sa.String(length=64), nullable=False),
        sa.Column("response_type", sa.String(length=32), nullable=False),
        sa.Column("client_id", sa.Uuid(), nullable=False),
        sa.Column("redirect_uri", sa.String(length=256), nullable=False),
        sa.Column("scope", sa.String(length=512), nullable=True),
        sa.Column("state", sa.String(length=512), nullable=True),
        sa.Column("nonce", sa.String(length=512), nullable=True),
        sa.Column("code_challenge", sa.String(length=43), nullable=False),
        sa.Column("code_challenge_method", sa.String(length=10), nullable=False),
        sa.Column("user_id", sa.Integer(), nullable=True),
        sa.Column("organization_id", sa.Integer(), nullable=True),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("used_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("(CURRENT_TIMESTAMP)"),
            nullable=False,
        ),
        sa.CheckConstraint(
            "code_challenge_method = 'S256'",
            name=op.f(
                "ck_oauth2_authorization_transaction_code_challenge_method_valid"
            ),
        ),
        sa.CheckConstraint(
            "response_type = 'code'",
            name=op.f("ck_oauth2_authorization_transaction_response_type_valid"),
        ),
        sa.CheckConstraint(
            "(user_id IS NULL AND organization_id IS NULL) OR (user_id IS NOT NULL AND organization_id IS NOT NULL)",
            name=op.f("ck_oauth2_authorization_transaction_principal_pair"),
        ),
        sa.CheckConstraint(
            "used_at IS NULL OR (user_id IS NOT NULL AND organization_id IS NOT NULL)",
            name=op.f("ck_oauth2_authorization_transaction_used_requires_principal"),
        ),
        sa.ForeignKeyConstraint(
            ["client_id"],
            ["oauth2_client.client_id"],
            name=op.f("fk_oauth2_authorization_transaction_client_id_oauth2_client"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["organization_id"],
            ["organization.id"],
            name=op.f(
                "fk_oauth2_authorization_transaction_organization_id_organization"
            ),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["user_id"],
            ["user.id"],
            name=op.f("fk_oauth2_authorization_transaction_user_id_user"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_oauth2_authorization_transaction")),
    )
    op.create_index(
        "uq_oauth2_auth_transaction_hash",
        "oauth2_authorization_transaction",
        ["transaction_hash"],
        unique=True,
    )
    op.create_index(
        op.f("ix_oauth2_authorization_transaction_expires_at"),
        "oauth2_authorization_transaction",
        ["expires_at"],
        unique=False,
    )
    op.create_index(
        op.f("ix_oauth2_authorization_transaction_organization_id"),
        "oauth2_authorization_transaction",
        ["organization_id"],
        unique=False,
    )
    op.create_index(
        op.f("ix_oauth2_authorization_transaction_user_id"),
        "oauth2_authorization_transaction",
        ["user_id"],
        unique=False,
    )
    op.create_table(
        "oauth2_client_machine_organization",
        sa.Column("client_id", sa.Integer(), nullable=False),
        sa.Column("organization_id", sa.Integer(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("(CURRENT_TIMESTAMP)"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["client_id"],
            ["oauth2_client.id"],
            name=op.f("fk_oauth2_client_machine_organization_client_id_oauth2_client"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["organization_id"],
            ["organization.id"],
            name=op.f(
                "fk_oauth2_client_machine_organization_organization_id_organization"
            ),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint(
            "client_id",
            "organization_id",
            name=op.f("pk_oauth2_client_machine_organization"),
        ),
    )
    op.create_index(
        op.f("ix_oauth2_client_machine_organization_organization_id"),
        "oauth2_client_machine_organization",
        ["organization_id"],
        unique=False,
    )
    op.create_table(
        "oauth2_client_user_organization",
        sa.Column("client_id", sa.Integer(), nullable=False),
        sa.Column("organization_id", sa.Integer(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("(CURRENT_TIMESTAMP)"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["client_id"],
            ["oauth2_client.id"],
            name=op.f("fk_oauth2_client_user_organization_client_id_oauth2_client"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["organization_id"],
            ["organization.id"],
            name=op.f(
                "fk_oauth2_client_user_organization_organization_id_organization"
            ),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint(
            "client_id",
            "organization_id",
            name=op.f("pk_oauth2_client_user_organization"),
        ),
    )
    op.create_index(
        op.f("ix_oauth2_client_user_organization_organization_id"),
        "oauth2_client_user_organization",
        ["organization_id"],
        unique=False,
    )
    op.create_table(
        "oauth2_device_authorization",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("device_code_hash", sa.String(length=64), nullable=False),
        sa.Column("user_code_hash", sa.String(length=64), nullable=False),
        sa.Column("client_id", sa.Uuid(), nullable=False),
        sa.Column("scope", sa.String(length=512), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("interval_seconds", sa.Integer(), nullable=False),
        sa.Column("last_polled_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("approved_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("denied_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("used_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("user_id", sa.Integer(), nullable=True),
        sa.Column("organization_id", sa.Integer(), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("(CURRENT_TIMESTAMP)"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("(CURRENT_TIMESTAMP)"),
            nullable=False,
        ),
        sa.CheckConstraint(
            "(approved_at IS NULL AND denied_at IS NULL AND used_at IS NULL AND user_id IS NULL AND organization_id IS NULL) OR (approved_at IS NOT NULL AND denied_at IS NULL AND user_id IS NOT NULL AND organization_id IS NOT NULL) OR (approved_at IS NULL AND denied_at IS NOT NULL AND used_at IS NULL AND user_id IS NOT NULL AND organization_id IS NOT NULL)",
            name=op.f("ck_oauth2_device_authorization_decision_state_valid"),
        ),
        sa.ForeignKeyConstraint(
            ["client_id"],
            ["oauth2_client.client_id"],
            name=op.f("fk_oauth2_device_authorization_client_id_oauth2_client"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["organization_id"],
            ["organization.id"],
            name=op.f("fk_oauth2_device_authorization_organization_id_organization"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["user_id"],
            ["user.id"],
            name=op.f("fk_oauth2_device_authorization_user_id_user"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_oauth2_device_authorization")),
    )
    op.create_index(
        op.f("ix_oauth2_device_authorization_expires_at"),
        "oauth2_device_authorization",
        ["expires_at"],
        unique=False,
    )
    op.create_index(
        op.f("ix_oauth2_device_authorization_organization_id"),
        "oauth2_device_authorization",
        ["organization_id"],
        unique=False,
    )
    op.create_index(
        op.f("ix_oauth2_device_authorization_user_id"),
        "oauth2_device_authorization",
        ["user_id"],
        unique=False,
    )
    op.create_index(
        "ix_oauth2_device_client_expires",
        "oauth2_device_authorization",
        ["client_id", "expires_at"],
        unique=False,
    )
    op.create_index(
        "uq_oauth2_device_code_hash",
        "oauth2_device_authorization",
        ["device_code_hash"],
        unique=True,
    )
    op.create_index(
        "uq_oauth2_user_code_hash",
        "oauth2_device_authorization",
        ["user_code_hash"],
        unique=True,
    )
    op.create_table(
        "oauth2_session",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("user_id", sa.Integer(), nullable=True),
        sa.Column("organization_id", sa.Integer(), nullable=True),
        sa.Column("client_id", sa.Uuid(), nullable=False),
        sa.Column("grant_type", sa.String(length=64), nullable=False),
        sa.Column("scope", sa.String(length=512), nullable=False),
        sa.Column("ended_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("public_id", sa.Uuid(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("(CURRENT_TIMESTAMP)"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("(CURRENT_TIMESTAMP)"),
            nullable=False,
        ),
        sa.CheckConstraint(
            "(grant_type = 'client_credentials' AND user_id IS NULL AND organization_id IS NULL) OR (grant_type IN ('authorization_code', 'urn:ietf:params:oauth:grant-type:device_code') AND user_id IS NOT NULL AND organization_id IS NOT NULL)",
            name=op.f("ck_oauth2_session_grant_principal_valid"),
        ),
        sa.CheckConstraint(
            "grant_type IN ('authorization_code', 'client_credentials', 'urn:ietf:params:oauth:grant-type:device_code')",
            name=op.f("ck_oauth2_session_grant_type_valid"),
        ),
        sa.ForeignKeyConstraint(
            ["client_id"],
            ["oauth2_client.client_id"],
            name=op.f("fk_oauth2_session_client_id_oauth2_client"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["organization_id"],
            ["organization.id"],
            name=op.f("fk_oauth2_session_organization_id_organization"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["user_id"],
            ["user.id"],
            name=op.f("fk_oauth2_session_user_id_user"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_oauth2_session")),
    )
    op.create_index(
        op.f("ix_oauth2_session_client_id"),
        "oauth2_session",
        ["client_id"],
        unique=False,
    )
    op.create_index(
        op.f("ix_oauth2_session_grant_type"),
        "oauth2_session",
        ["grant_type"],
        unique=False,
    )
    op.create_index(
        "ix_oauth2_session_organization_created",
        "oauth2_session",
        ["organization_id", "created_at"],
        unique=False,
    )
    op.create_index(
        op.f("ix_oauth2_session_public_id"),
        "oauth2_session",
        ["public_id"],
        unique=True,
    )
    op.create_index(
        "ix_oauth2_session_user_ended",
        "oauth2_session",
        ["user_id", "ended_at"],
        unique=False,
    )
    op.create_index(
        "ix_oauth2_session_user_organization_created",
        "oauth2_session",
        ["user_id", "organization_id", "created_at"],
        unique=False,
    )
    op.create_table(
        "organization_membership",
        sa.Column("user_id", sa.Integer(), nullable=False),
        sa.Column("organization_id", sa.Integer(), nullable=False),
        sa.Column(
            "role",
            sa.Enum(
                "member",
                "admin",
                name="organization_membership_role",
                native_enum=False,
            ),
            nullable=False,
        ),
        sa.CheckConstraint(
            "role IN ('member', 'admin')",
            name=op.f("ck_organization_membership_role_valid"),
        ),
        sa.ForeignKeyConstraint(
            ["organization_id"],
            ["organization.id"],
            name=op.f("fk_organization_membership_organization_id_organization"),
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["user_id"],
            ["user.id"],
            name=op.f("fk_organization_membership_user_id_user"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("user_id", name=op.f("pk_organization_membership")),
    )
    op.create_index(
        op.f("ix_organization_membership_organization_id"),
        "organization_membership",
        ["organization_id"],
        unique=False,
    )
    op.create_table(
        "user_email",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("user_id", sa.Integer(), nullable=False),
        sa.Column("email", sa.String(length=254), nullable=False),
        sa.Column("normalized_email", sa.String(length=254), nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("verified_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("retired_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("(CURRENT_TIMESTAMP)"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("(CURRENT_TIMESTAMP)"),
            nullable=False,
        ),
        sa.CheckConstraint(
            "status != 'current' OR retired_at IS NULL",
            name=op.f("ck_user_email_current_state"),
        ),
        sa.CheckConstraint(
            "status != 'pending' OR (verified_at IS NULL AND retired_at IS NULL)",
            name=op.f("ck_user_email_pending_state"),
        ),
        sa.CheckConstraint(
            "status != 'retired' OR retired_at IS NOT NULL",
            name=op.f("ck_user_email_retired_state"),
        ),
        sa.CheckConstraint(
            "status IN ('current', 'pending', 'retired')",
            name=op.f("ck_user_email_valid_status"),
        ),
        sa.ForeignKeyConstraint(
            ["user_id"],
            ["user.id"],
            name=op.f("fk_user_email_user_id_user"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_user_email")),
    )
    op.create_index(
        op.f("ix_user_email_user_id"), "user_email", ["user_id"], unique=False
    )
    op.create_index(
        "uq_user_email_active_normalized",
        "user_email",
        ["normalized_email"],
        unique=True,
        sqlite_where=sa.text("status IN ('current', 'pending')"),
    )
    op.create_index(
        "uq_user_email_current_user",
        "user_email",
        ["user_id"],
        unique=True,
        sqlite_where=sa.text("status = 'current'"),
    )
    op.create_index(
        "uq_user_email_pending_user",
        "user_email",
        ["user_id"],
        unique=True,
        sqlite_where=sa.text("status = 'pending'"),
    )
    op.create_table(
        "oauth2_refresh_token_history",
        sa.Column("token_hash", sa.String(length=64), nullable=False),
        sa.Column("session_id", sa.Integer(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("(CURRENT_TIMESTAMP)"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["session_id"],
            ["oauth2_session.id"],
            name=op.f("fk_oauth2_refresh_token_history_session_id_oauth2_session"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint(
            "token_hash", name=op.f("pk_oauth2_refresh_token_history")
        ),
    )
    op.create_index(
        op.f("ix_oauth2_refresh_token_history_session_id"),
        "oauth2_refresh_token_history",
        ["session_id"],
        unique=False,
    )
    op.create_table(
        "oauth2_token_state",
        sa.Column("session_id", sa.Integer(), nullable=False),
        sa.Column("access_token_hash", sa.String(length=64), nullable=False),
        sa.Column("access_jti", sa.String(length=64), nullable=False),
        sa.Column("refresh_token_hash", sa.String(length=64), nullable=True),
        sa.Column("access_expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("refresh_expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("(CURRENT_TIMESTAMP)"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("(CURRENT_TIMESTAMP)"),
            nullable=False,
        ),
        sa.CheckConstraint(
            "(refresh_token_hash IS NULL AND refresh_expires_at IS NULL) OR (refresh_token_hash IS NOT NULL AND refresh_expires_at IS NOT NULL)",
            name=op.f("ck_oauth2_token_state_refresh_pair"),
        ),
        sa.ForeignKeyConstraint(
            ["session_id"],
            ["oauth2_session.id"],
            name=op.f("fk_oauth2_token_state_session_id_oauth2_session"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("session_id", name=op.f("pk_oauth2_token_state")),
    )
    op.create_index(
        "ix_oauth2_token_state_access_expires",
        "oauth2_token_state",
        ["access_expires_at"],
        unique=False,
    )
    op.create_index(
        op.f("ix_oauth2_token_state_access_jti"),
        "oauth2_token_state",
        ["access_jti"],
        unique=True,
    )
    op.create_index(
        op.f("ix_oauth2_token_state_access_token_hash"),
        "oauth2_token_state",
        ["access_token_hash"],
        unique=True,
    )
    op.create_index(
        "ix_oauth2_token_state_refresh_expires",
        "oauth2_token_state",
        ["refresh_expires_at"],
        unique=False,
    )
    op.create_index(
        op.f("ix_oauth2_token_state_refresh_token_hash"),
        "oauth2_token_state",
        ["refresh_token_hash"],
        unique=True,
    )
    op.create_table(
        "user_workflow_token",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("user_email_id", sa.Integer(), nullable=False),
        sa.Column("purpose", sa.String(length=14), nullable=False),
        sa.Column("token_hash", sa.String(length=64), nullable=False),
        sa.Column("source_event_id", sa.String(length=32), nullable=True),
        sa.Column(
            "source_event_occurred_at", sa.DateTime(timezone=True), nullable=True
        ),
        sa.Column("derivation_key_id", sa.String(length=64), nullable=True),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("used_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("(CURRENT_TIMESTAMP)"),
            nullable=False,
        ),
        sa.CheckConstraint(
            "purpose IN ('verify_email', 'email_change', 'invite', 'reset_password')",
            name=op.f("ck_user_workflow_token_purpose_valid"),
        ),
        sa.CheckConstraint(
            "(source_event_id IS NULL AND source_event_occurred_at IS NULL AND derivation_key_id IS NULL) OR (source_event_id IS NOT NULL AND source_event_occurred_at IS NOT NULL AND derivation_key_id IS NOT NULL)",
            name=op.f("ck_user_workflow_token_event_derivation_fields"),
        ),
        sa.ForeignKeyConstraint(
            ["user_email_id"],
            ["user_email.id"],
            name=op.f("fk_user_workflow_token_user_email_id_user_email"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_user_workflow_token")),
        sa.UniqueConstraint(
            "source_event_id", name=op.f("uq_user_workflow_token_source_event_id")
        ),
        sa.UniqueConstraint(
            "token_hash", name=op.f("uq_user_workflow_token_token_hash")
        ),
    )
    op.create_index(
        op.f("ix_user_workflow_token_expires_at"),
        "user_workflow_token",
        ["expires_at"],
        unique=False,
    )
    op.create_index(
        op.f("ix_user_workflow_token_purpose"),
        "user_workflow_token",
        ["purpose"],
        unique=False,
    )
    op.create_index(
        op.f("ix_user_workflow_token_source_event_occurred_at"),
        "user_workflow_token",
        ["source_event_occurred_at"],
        unique=False,
    )
    op.create_index(
        op.f("ix_user_workflow_token_used_at"),
        "user_workflow_token",
        ["used_at"],
        unique=False,
    )
    op.create_index(
        op.f("ix_user_workflow_token_user_email_id"),
        "user_workflow_token",
        ["user_email_id"],
        unique=False,
    )
    op.create_index(
        "ix_oauth2_authorization_code_used_id",
        "oauth2_authorization_code",
        ["id"],
        unique=False,
        sqlite_where=sa.text("used_at IS NOT NULL"),
    )
    op.create_index(
        "ix_oauth2_authorization_transaction_used_id",
        "oauth2_authorization_transaction",
        ["id"],
        unique=False,
        sqlite_where=sa.text("used_at IS NOT NULL"),
    )
    op.create_index(
        "ix_oauth2_device_authorization_used_id",
        "oauth2_device_authorization",
        ["id"],
        unique=False,
        sqlite_where=sa.text("used_at IS NOT NULL"),
    )
    op.create_index(
        "ix_oauth2_device_authorization_denied_id",
        "oauth2_device_authorization",
        ["id"],
        unique=False,
        sqlite_where=sa.text("denied_at IS NOT NULL"),
    )
    op.create_index(
        "ix_oauth2_authorization_transaction_client_id",
        "oauth2_authorization_transaction",
        ["client_id"],
        unique=False,
    )


def downgrade() -> None:
    """Drop the complete canonical schema."""
    op.drop_index(
        "ix_oauth2_authorization_transaction_client_id",
        table_name="oauth2_authorization_transaction",
    )
    op.drop_index(
        "ix_oauth2_device_authorization_denied_id",
        table_name="oauth2_device_authorization",
    )
    op.drop_index(
        "ix_oauth2_device_authorization_used_id",
        table_name="oauth2_device_authorization",
    )
    op.drop_index(
        "ix_oauth2_authorization_transaction_used_id",
        table_name="oauth2_authorization_transaction",
    )
    op.drop_index(
        "ix_oauth2_authorization_code_used_id",
        table_name="oauth2_authorization_code",
    )
    op.drop_index(
        op.f("ix_user_workflow_token_user_email_id"), table_name="user_workflow_token"
    )
    op.drop_index(
        op.f("ix_user_workflow_token_used_at"), table_name="user_workflow_token"
    )
    op.drop_index(
        op.f("ix_user_workflow_token_source_event_occurred_at"),
        table_name="user_workflow_token",
    )
    op.drop_index(
        op.f("ix_user_workflow_token_purpose"), table_name="user_workflow_token"
    )
    op.drop_index(
        op.f("ix_user_workflow_token_expires_at"), table_name="user_workflow_token"
    )
    op.drop_table("user_workflow_token")
    op.drop_index(
        op.f("ix_oauth2_token_state_refresh_token_hash"),
        table_name="oauth2_token_state",
    )
    op.drop_index(
        "ix_oauth2_token_state_refresh_expires", table_name="oauth2_token_state"
    )
    op.drop_index(
        op.f("ix_oauth2_token_state_access_token_hash"), table_name="oauth2_token_state"
    )
    op.drop_index(
        op.f("ix_oauth2_token_state_access_jti"), table_name="oauth2_token_state"
    )
    op.drop_index(
        "ix_oauth2_token_state_access_expires", table_name="oauth2_token_state"
    )
    op.drop_table("oauth2_token_state")
    op.drop_index(
        op.f("ix_oauth2_refresh_token_history_session_id"),
        table_name="oauth2_refresh_token_history",
    )
    op.drop_table("oauth2_refresh_token_history")
    op.drop_index(
        "uq_user_email_pending_user",
        table_name="user_email",
        sqlite_where=sa.text("status = 'pending'"),
    )
    op.drop_index(
        "uq_user_email_current_user",
        table_name="user_email",
        sqlite_where=sa.text("status = 'current'"),
    )
    op.drop_index(
        "uq_user_email_active_normalized",
        table_name="user_email",
        sqlite_where=sa.text("status IN ('current', 'pending')"),
    )
    op.drop_index(op.f("ix_user_email_user_id"), table_name="user_email")
    op.drop_table("user_email")
    op.drop_index(
        op.f("ix_organization_membership_organization_id"),
        table_name="organization_membership",
    )
    op.drop_table("organization_membership")
    op.drop_index(
        "ix_oauth2_session_user_organization_created", table_name="oauth2_session"
    )
    op.drop_index("ix_oauth2_session_user_ended", table_name="oauth2_session")
    op.drop_index(op.f("ix_oauth2_session_public_id"), table_name="oauth2_session")
    op.drop_index("ix_oauth2_session_organization_created", table_name="oauth2_session")
    op.drop_index(op.f("ix_oauth2_session_grant_type"), table_name="oauth2_session")
    op.drop_index(op.f("ix_oauth2_session_client_id"), table_name="oauth2_session")
    op.drop_table("oauth2_session")
    op.drop_index("uq_oauth2_user_code_hash", table_name="oauth2_device_authorization")
    op.drop_index(
        "uq_oauth2_device_code_hash", table_name="oauth2_device_authorization"
    )
    op.drop_index(
        "ix_oauth2_device_client_expires", table_name="oauth2_device_authorization"
    )
    op.drop_index(
        op.f("ix_oauth2_device_authorization_user_id"),
        table_name="oauth2_device_authorization",
    )
    op.drop_index(
        op.f("ix_oauth2_device_authorization_organization_id"),
        table_name="oauth2_device_authorization",
    )
    op.drop_index(
        op.f("ix_oauth2_device_authorization_expires_at"),
        table_name="oauth2_device_authorization",
    )
    op.drop_table("oauth2_device_authorization")
    op.drop_index(
        op.f("ix_oauth2_client_user_organization_organization_id"),
        table_name="oauth2_client_user_organization",
    )
    op.drop_table("oauth2_client_user_organization")
    op.drop_index(
        op.f("ix_oauth2_client_machine_organization_organization_id"),
        table_name="oauth2_client_machine_organization",
    )
    op.drop_table("oauth2_client_machine_organization")
    op.drop_index(
        op.f("ix_oauth2_authorization_transaction_user_id"),
        table_name="oauth2_authorization_transaction",
    )
    op.drop_index(
        op.f("ix_oauth2_authorization_transaction_organization_id"),
        table_name="oauth2_authorization_transaction",
    )
    op.drop_index(
        op.f("ix_oauth2_authorization_transaction_expires_at"),
        table_name="oauth2_authorization_transaction",
    )
    op.drop_index(
        "uq_oauth2_auth_transaction_hash", table_name="oauth2_authorization_transaction"
    )
    op.drop_table("oauth2_authorization_transaction")
    op.drop_index(
        op.f("ix_oauth2_authorization_code_user_id"),
        table_name="oauth2_authorization_code",
    )
    op.drop_index(
        op.f("ix_oauth2_authorization_code_organization_id"),
        table_name="oauth2_authorization_code",
    )
    op.drop_index(
        op.f("ix_oauth2_authorization_code_expires_at"),
        table_name="oauth2_authorization_code",
    )
    op.drop_index("uq_oauth2_auth_code_hash", table_name="oauth2_authorization_code")
    op.drop_index(
        "ix_oauth2_auth_code_client_expires", table_name="oauth2_authorization_code"
    )
    op.drop_table("oauth2_authorization_code")
    op.drop_index("ix_browser_session_user_last_seen", table_name="browser_session")
    op.drop_index("ix_browser_session_user_expires", table_name="browser_session")
    op.drop_index(op.f("ix_browser_session_revoked_at"), table_name="browser_session")
    op.drop_index(op.f("ix_browser_session_public_id"), table_name="browser_session")
    op.drop_index(op.f("ix_browser_session_expires_at"), table_name="browser_session")
    op.drop_index(
        op.f("ix_browser_session_absolute_expires_at"), table_name="browser_session"
    )
    op.drop_table("browser_session")
    op.drop_index(op.f("ix_user_public_id"), table_name="user")
    op.drop_table("user")
    op.drop_index(op.f("ix_organization_public_id"), table_name="organization")
    op.drop_index(op.f("ix_organization_name"), table_name="organization")
    op.drop_table("organization")
    op.drop_table("oauth2_client")
    op.drop_index(
        op.f("ix_notification_outbox_processed_at"), table_name="notification_outbox"
    )
    op.drop_index(
        op.f("ix_notification_outbox_event_type"), table_name="notification_outbox"
    )
    op.drop_index(
        op.f("ix_notification_outbox_claimed_at"), table_name="notification_outbox"
    )
    op.drop_index(
        op.f("ix_notification_outbox_available_at"), table_name="notification_outbox"
    )
    op.drop_table("notification_outbox")
