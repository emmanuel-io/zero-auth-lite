"""User domain specification."""

from typing import Final

from app.core.specs import EMAIL_ADDRESS_LENGTH_MAX


class UserSpecs:
    """Namespace for User constraints and domain constants.

    Keep this module import-free and limited to constants and simple helpers.
    """

    FIRST_NAME_LENGTH_MAX: Final[int] = 64
    LAST_NAME_LENGTH_MAX: Final[int] = 64
    EMAIL_LENGTH_MAX: Final[int] = EMAIL_ADDRESS_LENGTH_MAX
    GENERATED_PASSWORD_BYTES: Final[int] = 32
