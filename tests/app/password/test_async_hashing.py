"""Tests for the async password-hashing boundary."""

import threading

import pytest
from app.password.async_hashing import hash_password, verify_password


pytestmark = pytest.mark.unit


class RecordingPasswordHasher:
    """Record the worker thread used by synchronous hashing operations."""

    def __init__(self) -> None:
        """Initialize the worker-thread recording list."""
        self.thread_ids: list[int] = []

    def hash(self, password: str) -> str:
        """Return a deterministic test hash."""
        self.thread_ids.append(threading.get_ident())
        return f"hashed:{password}"

    def verify(self, *, password: str, password_hash: str) -> bool:
        """Verify the deterministic test hash."""
        self.thread_ids.append(threading.get_ident())
        return password_hash == f"hashed:{password}"


@pytest.mark.asyncio
async def test_password_operations_run_outside_the_event_loop_thread() -> None:
    """Keep CPU-bound providers away from the event-loop thread."""
    event_loop_thread = threading.get_ident()
    password_hasher = RecordingPasswordHasher()

    password_hash = await hash_password(password_hasher, "secret")
    valid = await verify_password(
        password_hasher,
        password="secret",  # noqa: S106
        password_hash=password_hash,
    )

    assert valid is True
    assert password_hasher.thread_ids
    assert all(
        thread_id != event_loop_thread for thread_id in password_hasher.thread_ids
    )
