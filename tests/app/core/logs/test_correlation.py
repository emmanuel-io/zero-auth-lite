"""Tests for the canonical correlation identifier representation."""

import pytest
from app.core.logs.correlation import (
    CORRELATION_ID_LENGTH,
    generate_correlation_id,
    normalize_correlation_id,
)


pytestmark = pytest.mark.unit


def test_generated_correlation_id_is_uuid_hex() -> None:
    """Generate the persisted 16-byte UUID representation without separators."""
    correlation_id = generate_correlation_id()

    assert len(correlation_id) == CORRELATION_ID_LENGTH
    assert correlation_id == correlation_id.lower()
    assert int(correlation_id, 16) >= 0


def test_correlation_id_normalizes_hyphenated_uuid() -> None:
    """Use one representation in headers, logs, and durable outbox rows."""
    normalized = normalize_correlation_id("550e8400-e29b-41d4-a716-446655440000")

    assert normalized == "550e8400e29b41d4a716446655440000"
