"""Pydantic schemas for reusable session authentication routes."""

from typing import Annotated

from pydantic import BaseModel, ConfigDict, Field

from app.browser_sessions.enums import LogoutScope
from app.password.validation import PasswordInput


class LoginRequest(BaseModel):
    """User login request."""

    model_config = ConfigDict(extra="forbid")

    username: Annotated[
        str,
        Field(
            description="User email address.",
            json_schema_extra={"example": "bob@squaresponge.com"},
        ),
    ]

    password: Annotated[
        PasswordInput,
        Field(
            description="User password.",
            json_schema_extra={"example": "S3cret!pass", "writeOnly": True},
        ),
    ]


class LogoutRequest(BaseModel):
    """Browser sessions selected by a logout request."""

    model_config = ConfigDict(extra="forbid")

    scope: LogoutScope = LogoutScope.CURRENT
