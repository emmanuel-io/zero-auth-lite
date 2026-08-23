"""Public payloads returned for application HTTP errors."""

from pydantic import BaseModel, Field


class ErrorDetail(BaseModel):
    """One structured explanation attached to an application error."""

    location: list[str | int] = Field(
        description="Path to the value that caused the error"
    )
    message: str = Field(description="Human-readable explanation of this detail")
    type: str = Field(description="Stable category for this detail")


class ErrorResponse(BaseModel):
    """Structured payload shared by application error responses."""

    code: str = Field(description="Application-level error code")
    message: str = Field(description="Human-readable error message")
    details: list[ErrorDetail] = Field(
        description="Structured explanations associated with the error"
    )
