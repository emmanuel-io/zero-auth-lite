"""Typed paths for OAuth2 client administration routes."""

from typing import Annotated

from fastapi import Path
from pydantic import UUID4


OAUTH2_CLIENTS_PREFIX = "/oauth2/clients"
OAuth2ClientIdPath = Annotated[
    UUID4,
    Path(
        description="Global OAuth2 client UUID.",
    ),
]
