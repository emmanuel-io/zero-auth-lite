"""Single-node process lock for first-run bootstrap."""

import fcntl
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path


@contextmanager
def serialized_bootstrap(
    lock_directory: Path, *, lock_filename: str = "initial-operator.lock"
) -> Iterator[None]:
    """Serialize bootstrap work across processes sharing one runtime directory.

    Args:
        lock_directory: Ephemeral directory shared by application workers.
        lock_filename: File name identifying the serialized local operation.

    Yields:
        Control while this process owns the bootstrap lock.

    Raises:
        RuntimeError: If the lock directory or file cannot be used.
    """
    try:
        lock_directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    except OSError as exc:
        msg = f"Cannot create bootstrap lock directory {lock_directory}."
        raise RuntimeError(msg) from exc
    if not lock_directory.is_dir():
        msg = f"Bootstrap lock path {lock_directory} is not a directory."
        raise RuntimeError(msg)

    path = lock_directory / lock_filename
    try:
        handle = path.open(mode="a+", encoding="ascii")
    except OSError as exc:
        msg = f"Cannot open bootstrap lock file {path}."
        raise RuntimeError(msg) from exc
    locked = False
    try:
        try:
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
            locked = True
        except OSError as exc:
            msg = f"Cannot acquire bootstrap lock file {path}."
            raise RuntimeError(msg) from exc
        yield
    finally:
        try:
            if locked:
                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
        finally:
            handle.close()
