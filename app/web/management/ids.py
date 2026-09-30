"""Typed public identifiers accepted by management browser routes."""

from typing import Annotated

from fastapi import Path
from pydantic import UUID4


OrganizationIdPath = Annotated[UUID4, Path()]
UserIdPath = Annotated[UUID4, Path()]
OAuth2SessionIdPath = Annotated[UUID4, Path()]
OAuth2ClientIdPath = Annotated[UUID4, Path()]
