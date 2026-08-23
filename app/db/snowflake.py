"""Process-safe Snowflake public identifier generation."""

from __future__ import annotations

import fcntl
import time
from dataclasses import dataclass
from threading import Lock
from typing import IO, TYPE_CHECKING


if TYPE_CHECKING:
    from pathlib import Path

from app.public_ids import PublicId


SNOWFLAKE_EPOCH_MS = 1_704_067_200_000
SNOWFLAKE_NODE_ID_BITS = 10
SNOWFLAKE_SEQUENCE_BITS = 12
SNOWFLAKE_MAX_NODE_ID = (1 << SNOWFLAKE_NODE_ID_BITS) - 1
SNOWFLAKE_MAX_SEQUENCE = (1 << SNOWFLAKE_SEQUENCE_BITS) - 1
SNOWFLAKE_NODE_ID_SHIFT = SNOWFLAKE_SEQUENCE_BITS
SNOWFLAKE_TIMESTAMP_SHIFT = SNOWFLAKE_NODE_ID_BITS + SNOWFLAKE_SEQUENCE_BITS

_snowflake_lock = Lock()
_snowflake_node_id: int | None = None
_snowflake_last_timestamp_ms = -1
_snowflake_sequence = 0


@dataclass
class SnowflakeNodeLease:
    """Exclusive process lease for one Snowflake node identifier."""

    node_id: int
    path: Path
    automatic: bool
    _handle: IO[str]
    _released: bool = False

    def release(self) -> None:
        """Release the operating-system lock held by this process."""
        if self._released:
            return
        try:
            fcntl.flock(self._handle.fileno(), fcntl.LOCK_UN)
        finally:
            self._handle.close()
            self._released = True


def _validate_node_id(node_id: int) -> None:
    """Reject a node identifier that does not fit the Snowflake layout."""
    if node_id < 0 or node_id > SNOWFLAKE_MAX_NODE_ID:
        msg = f"Snowflake node ID must be between 0 and {SNOWFLAKE_MAX_NODE_ID}."
        raise ValueError(msg)


def _try_acquire_node(
    *,
    lock_directory: Path,
    node_id: int,
    automatic: bool,
) -> SnowflakeNodeLease | None:
    """Try to reserve one node without waiting for another process."""
    path = lock_directory / f"node-{node_id}.lock"
    handle = path.open(mode="a+", encoding="ascii")
    try:
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        handle.close()
        return None
    return SnowflakeNodeLease(
        node_id=node_id,
        path=path,
        automatic=automatic,
        _handle=handle,
    )


def acquire_snowflake_node_lease(
    *,
    lock_directory: Path,
    requested_node_id: int | None,
) -> SnowflakeNodeLease:
    """Reserve one process-local Snowflake node using a POSIX file lock.

    Args:
        lock_directory: Directory shared by every worker on the application host.
        requested_node_id: Exact node to reserve, or ``None`` for automatic choice.

    Returns:
        The lease that must remain open for the worker lifetime.

    Raises:
        RuntimeError: If the directory is unavailable or no requested node is free.
        ValueError: If an explicit node identifier is outside the 10-bit range.
    """
    if requested_node_id is not None:
        _validate_node_id(requested_node_id)
    try:
        lock_directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    except OSError as exc:
        msg = f"Cannot create Snowflake lock directory {lock_directory}."
        raise RuntimeError(msg) from exc
    if not lock_directory.is_dir():
        msg = f"Snowflake lock path {lock_directory} is not a directory."
        raise RuntimeError(msg)

    if requested_node_id is not None:
        try:
            lease = _try_acquire_node(
                lock_directory=lock_directory,
                node_id=requested_node_id,
                automatic=False,
            )
        except OSError as exc:
            msg = f"Cannot open Snowflake lock files in {lock_directory}."
            raise RuntimeError(msg) from exc
        if lease is None:
            msg = f"Snowflake node ID {requested_node_id} is already in use."
            raise RuntimeError(msg)
        return lease

    try:
        for node_id in range(SNOWFLAKE_MAX_NODE_ID + 1):
            lease = _try_acquire_node(
                lock_directory=lock_directory,
                node_id=node_id,
                automatic=True,
            )
            if lease is not None:
                return lease
    except OSError as exc:
        msg = f"Cannot open Snowflake lock files in {lock_directory}."
        raise RuntimeError(msg) from exc
    msg = f"No Snowflake node ID is available in {lock_directory}."
    raise RuntimeError(msg)


def current_timestamp_ms() -> int:
    """Return the current Unix timestamp in milliseconds."""
    return time.time_ns() // 1_000_000


def wait_for_next_millisecond(last_timestamp_ms: int) -> int:
    """Wait until the clock moves past the provided timestamp."""
    timestamp_ms = current_timestamp_ms()
    while timestamp_ms <= last_timestamp_ms:
        timestamp_ms = current_timestamp_ms()
    return timestamp_ms


def configure_snowflake_generator(node_id: int) -> None:
    """Configure this process after it has acquired an exclusive node lease."""
    global _snowflake_last_timestamp_ms, _snowflake_node_id  # noqa: PLW0603
    global _snowflake_sequence  # noqa: PLW0603

    _validate_node_id(node_id)
    with _snowflake_lock:
        if _snowflake_node_id is not None:
            msg = "Snowflake generator is already configured in this process."
            raise RuntimeError(msg)
        acquired_at_ms = current_timestamp_ms()
        first_safe_timestamp_ms = wait_for_next_millisecond(acquired_at_ms)
        _snowflake_node_id = node_id
        _snowflake_last_timestamp_ms = first_safe_timestamp_ms - 1
        _snowflake_sequence = 0


def unconfigure_snowflake_generator() -> None:
    """Prevent further generation after the worker releases its node lease."""
    global _snowflake_last_timestamp_ms, _snowflake_node_id  # noqa: PLW0603
    global _snowflake_sequence  # noqa: PLW0603

    with _snowflake_lock:
        _snowflake_node_id = None
        _snowflake_last_timestamp_ms = -1
        _snowflake_sequence = 0


def configured_snowflake_node_id() -> int | None:
    """Return the node configured in this process, if any."""
    with _snowflake_lock:
        return _snowflake_node_id


def generate_snowflake_id() -> PublicId:
    """Generate a Snowflake-style 64-bit public identifier."""
    global _snowflake_last_timestamp_ms, _snowflake_sequence  # noqa: PLW0603

    with _snowflake_lock:
        if _snowflake_node_id is None:
            msg = "Snowflake generator is not configured for this process."
            raise RuntimeError(msg)
        timestamp_ms = current_timestamp_ms()
        if timestamp_ms < _snowflake_last_timestamp_ms:
            msg = "System clock moved backwards while generating a public ID."
            raise RuntimeError(msg)

        if timestamp_ms == _snowflake_last_timestamp_ms:
            _snowflake_sequence = (_snowflake_sequence + 1) & SNOWFLAKE_MAX_SEQUENCE
            if _snowflake_sequence == 0:
                timestamp_ms = wait_for_next_millisecond(_snowflake_last_timestamp_ms)
        else:
            _snowflake_sequence = 0

        _snowflake_last_timestamp_ms = timestamp_ms
        snowflake_id = (
            ((timestamp_ms - SNOWFLAKE_EPOCH_MS) << SNOWFLAKE_TIMESTAMP_SHIFT)
            | (_snowflake_node_id << SNOWFLAKE_NODE_ID_SHIFT)
            | _snowflake_sequence
        )
        return PublicId(snowflake_id)
