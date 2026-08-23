"""HTTP schemas for OAuth2 client credential rotation."""

from typing import Annotated

from pydantic import BaseModel, Field


class OAuth2ClientSecretResponse(BaseModel):
    """Response payload for creating a replacement OAuth2 client secret."""

    client_id: Annotated[str, Field(description="Global OAuth2 client identifier.")]
    client_secret: Annotated[
        str,
        Field(
            description=(
                "Raw replacement secret returned once. It cannot be retrieved "
                "after this response."
            )
        ),
    ]
