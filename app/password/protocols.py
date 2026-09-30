"""Protocols for password hashing and verification."""

from typing import Protocol


class PasswordHasherError(Exception):
    """Base exception for password hasher errors."""


class PasswordHasherProtocol(Protocol):
    """Protocol for password hashing and verification."""

    def hash(self, password: str) -> str:
        """Hash a plaintext password into a self-contained verification value.

        Raises:
            PasswordHasherError: If there was an error hashing the password.
        """
        ...

    def verify(self, *, password: str, password_hash: str) -> bool:
        """Return whether a plaintext password matches a stored hash.

        Raises:
            PasswordHasherError: If there was an error verifying the password.
        """
        ...

    def verify_and_update(
        self, *, password: str, password_hash: str
    ) -> tuple[bool, str | None]:
        """Verify a password and return a replacement hash when policy changed.

        Raises:
            PasswordHasherError: If verification or replacement hashing fails.
        """
        ...
