"""Protocols for password hashing and verification."""

from typing import Protocol


class PasswordHasherError(Exception):
    """Base exception for password hasher errors."""


class PasswordHasherProtocol(Protocol):
    """Protocol for password hashing and verification."""

    def hash(self, password: str) -> str:
        """Hash a plaintext password into a self-contained verification value.

        Args:
            password (str): The plaintext password to hash.

        Returns:
            str: The hashed password.

        Raises:
            PasswordHasherError: If there was an error hashing the password.
        """
        ...

    def verify(self, *, password: str, password_hash: str) -> bool:
        """Verify a plaintext password against a stored hash.

        Args:
            password (str): The plaintext password to verify.
            password_hash (str): The hashed password to compare against.

        Returns:
            bool: True if the password is correct, False otherwise.

        Raises:
            PasswordHasherError: If there was an error verifying the password.
        """
        ...
