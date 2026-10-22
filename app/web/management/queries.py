"""Pagination shared by management browser lists."""

from pydantic import BaseModel, ConfigDict, Field


class ManagementPagination(BaseModel):
    """Flat pagination fields that can accompany filters and notices."""

    # Each query model sees sibling fields too; browser lists ignore extras.
    model_config = ConfigDict(extra="ignore")

    offset: int = Field(default=0, ge=0)
    limit: int = Field(default=20, ge=1, le=100)
