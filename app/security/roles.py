"""Application role identifiers used by authorization decisions."""

from enum import StrEnum


class Role(StrEnum):
    """Role identifiers used across the canonical server.

    Notes:
        - OPERATOR: manages the Zero Auth Lite control plane.
        - ORGANIZATION_ADMIN: admin inside current organization only.
    """

    OPERATOR = "operator"
    ORGANIZATION_ADMIN = "organization_admin"
