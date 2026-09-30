"""Typed UUID path parameters for application-owned APIs."""

from typing import Annotated

from fastapi import Path
from pydantic import UUID4


UserIdPath = Annotated[
    UUID4,
    Path(
        description="User UUID.",
        examples=["550e8400-e29b-41d4-a716-446655440000"],
    ),
]
OrganizationIdPath = Annotated[
    UUID4,
    Path(
        description="Organization UUID.",
        examples=["550e8400-e29b-41d4-a716-446655440000"],
    ),
]
