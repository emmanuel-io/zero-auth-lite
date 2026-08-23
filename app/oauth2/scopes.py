"""Shared OAuth2 scope validation primitives."""

from typing import Annotated

from pydantic import Field

from app.oauth2.specs import OAuth2Specs


SCOPE_NAME_PATTERN = r"^[\x21\x23-\x5B\x5D-\x7E]+$"
ScopeName = Annotated[
    str,
    Field(
        min_length=1,
        max_length=OAuth2Specs.SCOPE_NAME_LENGTH_MAX,
        pattern=SCOPE_NAME_PATTERN,
    ),
]
