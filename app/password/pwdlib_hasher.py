"""Default password hasher implementation based on pwdlib."""

from logging import getLogger

from pwdlib import PasswordHash
from pwdlib.exceptions import PwdlibError

from app.password.protocols import PasswordHasherError


logger = getLogger(__name__)


class PwdlibPasswordHasher:
    """Default pwdlib password hasher provider."""

    def __init__(self) -> None:
        """Initialize the default password hasher."""
        self._hasher = PasswordHash.recommended()

    def hash(self, password: str) -> str:
        """Hash a plaintext password using the configured pwdlib policy."""
        try:
            return self._hasher.hash(password)
        except PwdlibError as exc:
            logger.exception("Password hashing failed")
            raise PasswordHasherError from exc

    def verify(self, *, password: str, password_hash: str) -> bool:
        """Verify a plaintext password against a stored hash."""
        try:
            return self._hasher.verify(password=password, hash=password_hash)
        except PwdlibError as exc:
            logger.exception("Password verification failed")
            raise PasswordHasherError from exc
