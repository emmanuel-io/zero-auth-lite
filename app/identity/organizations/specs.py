"""Organization domain specification."""

from typing import Final


class OrganizationSpecs:
    """Namespace for Organization constraints and domain constants.

    Keep this module import-free and limited to constants and simple helpers.
    """

    NAME_LENGTH_MAX: Final[int] = 32
