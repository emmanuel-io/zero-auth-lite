"""Validated organization domain value types."""

from typing import Annotated

from pydantic import StringConstraints

from app.identity.organizations.specs import OrganizationSpecs


OrganizationName = Annotated[
    str,
    StringConstraints(
        strip_whitespace=True,
        min_length=1,
        max_length=OrganizationSpecs.NAME_LENGTH_MAX,
    ),
]
