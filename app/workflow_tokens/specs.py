"""Shared contracts for single-use workflow tokens."""

from typing import Final

from app.core.specs import unpadded_urlsafe_base64_length, UUID_HEX_LENGTH
from app.workflow_tokens.enums import WorkflowTokenPurpose


class WorkflowTokenSpecs:
    """Workflow-token persistence and validation limits."""

    RANDOM_TOKEN_BYTES: Final[int] = 32
    RAW_TOKEN_LENGTH_MIN: Final[int] = 16
    RAW_TOKEN_LENGTH_MAX: Final[int] = unpadded_urlsafe_base64_length(
        RANDOM_TOKEN_BYTES
    )
    PURPOSE_LENGTH_MAX: Final[int] = max(
        len(purpose.value) for purpose in WorkflowTokenPurpose
    )
    SOURCE_EVENT_ID_LENGTH: Final[int] = UUID_HEX_LENGTH
    DERIVATION_KEY_ID_LENGTH_MAX: Final[int] = 64
