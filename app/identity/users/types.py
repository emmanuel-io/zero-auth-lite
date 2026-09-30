"""Validated user domain value types."""

from typing import Annotated

from pydantic import EmailStr, Field, StringConstraints

from app.identity.users.specs import UserSpecs


UserFirstName = Annotated[
    str,
    StringConstraints(
        max_length=UserSpecs.FIRST_NAME_LENGTH_MAX,
        pattern=r"^[^\r\n]*$",
    ),
]

UserLastName = Annotated[
    str,
    StringConstraints(
        max_length=UserSpecs.LAST_NAME_LENGTH_MAX,
        pattern=r"^[^\r\n]*$",
    ),
]

UserEmail = Annotated[
    EmailStr,
    Field(max_length=UserSpecs.EMAIL_LENGTH_MAX),
]
