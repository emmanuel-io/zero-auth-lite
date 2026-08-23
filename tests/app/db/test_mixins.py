"""Tests for Snowflake public identifier generation."""

from collections.abc import Iterator
from pathlib import Path

import pytest

from app.db import snowflake


pytestmark = pytest.mark.unit

VALID_NODE_ID = 7
NEXT_TIMESTAMP = 101


@pytest.fixture(autouse=True)
def reset_generator() -> Iterator[None]:
    """Keep process-global generator state isolated between unit tests."""
    snowflake.unconfigure_snowflake_generator()
    yield
    snowflake.unconfigure_snowflake_generator()


def test_generate_snowflake_id_requires_process_configuration() -> None:
    """Reject generation before the worker owns a node lease."""
    with pytest.raises(RuntimeError, match="not configured"):
        snowflake.generate_snowflake_id()


def test_wait_for_next_millisecond_loops_until_clock_advances(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Assert wait helper keeps polling until the timestamp advances."""
    timestamps = iter([100, 100, 101])
    monkeypatch.setattr(snowflake, "current_timestamp_ms", lambda: next(timestamps))

    assert snowflake.wait_for_next_millisecond(100) == NEXT_TIMESTAMP


@pytest.mark.negative
def test_generate_snowflake_id_rejects_clock_regression(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Assert public ID generation rejects backward clocks."""
    monkeypatch.setattr(snowflake, "current_timestamp_ms", lambda: 200)
    monkeypatch.setattr(snowflake, "wait_for_next_millisecond", lambda _last: 201)
    snowflake.configure_snowflake_generator(VALID_NODE_ID)
    monkeypatch.setattr(snowflake, "current_timestamp_ms", lambda: 199)

    with pytest.raises(RuntimeError, match="clock moved backwards"):
        snowflake.generate_snowflake_id()


def test_generate_snowflake_id_increments_sequence_and_waits_on_wrap(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Assert same-millisecond generation increments and wraps sequence."""
    monkeypatch.setattr(snowflake, "current_timestamp_ms", lambda: 299)
    monkeypatch.setattr(snowflake, "wait_for_next_millisecond", lambda _last: 300)
    snowflake.configure_snowflake_generator(VALID_NODE_ID)
    monkeypatch.setattr(snowflake, "current_timestamp_ms", lambda: 300)

    first_id = snowflake.generate_snowflake_id()

    monkeypatch.setattr(snowflake, "_snowflake_last_timestamp_ms", 400)
    monkeypatch.setattr(
        snowflake,
        "_snowflake_sequence",
        snowflake.SNOWFLAKE_MAX_SEQUENCE,
    )
    monkeypatch.setattr(snowflake, "current_timestamp_ms", lambda: 400)
    monkeypatch.setattr(snowflake, "wait_for_next_millisecond", lambda _last: 401)

    wrapped_id = snowflake.generate_snowflake_id()

    assert int(first_id) & snowflake.SNOWFLAKE_MAX_SEQUENCE == 0
    assert int(wrapped_id) > int(first_id)


def test_node_leases_are_distinct_and_reusable(tmp_path: Path) -> None:
    """Allocate distinct active nodes and reuse one only after release."""
    first = snowflake.acquire_snowflake_node_lease(
        lock_directory=tmp_path,
        requested_node_id=None,
    )
    second = snowflake.acquire_snowflake_node_lease(
        lock_directory=tmp_path,
        requested_node_id=None,
    )
    try:
        assert first.node_id == 0
        assert second.node_id == 1
    finally:
        first.release()
        second.release()

    reused = snowflake.acquire_snowflake_node_lease(
        lock_directory=tmp_path,
        requested_node_id=None,
    )
    try:
        assert reused.node_id == 0
    finally:
        reused.release()


@pytest.mark.negative
def test_explicit_node_lease_rejects_contention(tmp_path: Path) -> None:
    """Fail instead of sharing an explicitly requested node."""
    lease = snowflake.acquire_snowflake_node_lease(
        lock_directory=tmp_path,
        requested_node_id=VALID_NODE_ID,
    )
    try:
        with pytest.raises(RuntimeError, match="already in use"):
            snowflake.acquire_snowflake_node_lease(
                lock_directory=tmp_path,
                requested_node_id=VALID_NODE_ID,
            )
    finally:
        lease.release()


@pytest.mark.negative
def test_automatic_node_lease_rejects_exhaustion(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Fail startup when every node in the configured pool is active."""
    monkeypatch.setattr(snowflake, "SNOWFLAKE_MAX_NODE_ID", 1)
    first = snowflake.acquire_snowflake_node_lease(
        lock_directory=tmp_path,
        requested_node_id=None,
    )
    second = snowflake.acquire_snowflake_node_lease(
        lock_directory=tmp_path,
        requested_node_id=None,
    )
    try:
        with pytest.raises(RuntimeError, match="No Snowflake node ID"):
            snowflake.acquire_snowflake_node_lease(
                lock_directory=tmp_path,
                requested_node_id=None,
            )
    finally:
        first.release()
        second.release()
