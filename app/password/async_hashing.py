"""Async boundary for CPU-bound password hashing operations."""

import asyncio

from app.password.protocols import PasswordHasherProtocol


async def hash_password(password_hasher: PasswordHasherProtocol, password: str) -> str:
    """Hash a password in a worker thread without blocking the event loop."""
    return await asyncio.to_thread(password_hasher.hash, password)


async def verify_password(
    password_hasher: PasswordHasherProtocol, *, password: str, password_hash: str
) -> bool:
    """Verify a password in a worker thread without blocking the event loop."""
    return await asyncio.to_thread(
        password_hasher.verify,
        password=password,
        password_hash=password_hash,
    )


async def verify_and_update_password(
    password_hasher: PasswordHasherProtocol, *, password: str, password_hash: str
) -> tuple[bool, str | None]:
    """Verify and optionally upgrade a password hash in a worker thread."""
    return await asyncio.to_thread(
        password_hasher.verify_and_update,
        password=password,
        password_hash=password_hash,
    )
