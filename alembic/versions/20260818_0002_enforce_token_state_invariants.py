"""Enforce coherent authorization and token states."""
# ruff: noqa: INP001

from alembic import op


revision: str = "20260818_0002"
down_revision: str | None = "20260817_0001"
branch_labels: str | None = None
depends_on: str | None = None


def upgrade() -> None:
    """Reject contradictory persisted authorization and token states."""
    with op.batch_alter_table("oauth2_authorization_transaction") as batch_op:
        batch_op.create_check_constraint(
            op.f("ck_oauth2_authorization_transaction_principal_pair"),
            "(user_id IS NULL AND organization_id IS NULL) OR "
            "(user_id IS NOT NULL AND organization_id IS NOT NULL)",
        )
        batch_op.create_check_constraint(
            op.f("ck_oauth2_authorization_transaction_used_requires_principal"),
            "used_at IS NULL OR (user_id IS NOT NULL AND organization_id IS NOT NULL)",
        )

    with op.batch_alter_table("oauth2_device_authorization") as batch_op:
        batch_op.create_check_constraint(
            op.f("ck_oauth2_device_authorization_decision_state_valid"),
            "(approved_at IS NULL AND denied_at IS NULL AND used_at IS NULL "
            "AND user_id IS NULL AND organization_id IS NULL) OR "
            "(approved_at IS NOT NULL AND denied_at IS NULL "
            "AND user_id IS NOT NULL AND organization_id IS NOT NULL) OR "
            "(approved_at IS NULL AND denied_at IS NOT NULL AND used_at IS NULL "
            "AND user_id IS NOT NULL AND organization_id IS NOT NULL)",
        )

    with op.batch_alter_table("oauth2_token_pair") as batch_op:
        batch_op.create_check_constraint(
            op.f("ck_oauth2_token_pair_refresh_pair"),
            "(refresh_token_hash IS NULL AND refresh_expires_at IS NULL) OR "
            "(refresh_token_hash IS NOT NULL AND refresh_expires_at IS NOT NULL)",
        )
        batch_op.create_check_constraint(
            op.f("ck_oauth2_token_pair_principal_pair"),
            "(user_id IS NULL AND organization_id IS NULL) OR "
            "(user_id IS NOT NULL AND organization_id IS NOT NULL)",
        )

    with op.batch_alter_table("user_auth_token") as batch_op:
        batch_op.create_check_constraint(
            op.f("ck_user_auth_token_event_derivation_fields"),
            "(source_event_id IS NULL AND source_event_occurred_at IS NULL "
            "AND derivation_key_id IS NULL) OR "
            "(source_event_id IS NOT NULL AND source_event_occurred_at IS NOT NULL "
            "AND derivation_key_id IS NOT NULL)",
        )


def downgrade() -> None:
    """Remove authorization and token state check constraints."""
    with op.batch_alter_table("user_auth_token") as batch_op:
        batch_op.drop_constraint(
            op.f("ck_user_auth_token_event_derivation_fields"), type_="check"
        )

    with op.batch_alter_table("oauth2_token_pair") as batch_op:
        batch_op.drop_constraint(
            op.f("ck_oauth2_token_pair_principal_pair"), type_="check"
        )
        batch_op.drop_constraint(
            op.f("ck_oauth2_token_pair_refresh_pair"), type_="check"
        )

    with op.batch_alter_table("oauth2_device_authorization") as batch_op:
        batch_op.drop_constraint(
            op.f("ck_oauth2_device_authorization_decision_state_valid"),
            type_="check",
        )

    with op.batch_alter_table("oauth2_authorization_transaction") as batch_op:
        batch_op.drop_constraint(
            op.f("ck_oauth2_authorization_transaction_used_requires_principal"),
            type_="check",
        )
        batch_op.drop_constraint(
            op.f("ck_oauth2_authorization_transaction_principal_pair"),
            type_="check",
        )
