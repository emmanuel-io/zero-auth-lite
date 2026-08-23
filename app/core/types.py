"""Pydantic value types shared across application domains."""

from typing import Annotated

from pydantic import EmailStr, Field

from app.core.specs import EMAIL_ADDRESS_LENGTH_MAX


EmailValue = Annotated[EmailStr, Field(max_length=EMAIL_ADDRESS_LENGTH_MAX)]
