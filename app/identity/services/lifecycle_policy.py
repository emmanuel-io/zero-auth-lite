"""Policy values shared by user lifecycle collaborators."""

from enum import StrEnum


class EmailUpdatePolicy(StrEnum):
    """Define how a changed user email enters the verification workflow."""

    PENDING_VERIFICATION_ONLY = "pending_verification_only"
    DIRECT_IF_UNVERIFIED = "direct_if_unverified"
