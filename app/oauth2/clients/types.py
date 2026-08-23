"""Validated OAuth2 client domain value types."""

from typing import Annotated

from pydantic import StringConstraints

from app.oauth2.specs import OAuth2Specs


OAuth2ClientName = Annotated[
    str,
    StringConstraints(
        strip_whitespace=True,
        min_length=1,
        max_length=OAuth2Specs.CLIENT_NAME_LENGTH_MAX,
    ),
]
