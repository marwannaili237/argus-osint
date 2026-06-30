"""
Argus OSINT – Target Schemas (Pydantic v2)

Request / response models for target CRUD operations.
"""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, Field


class TargetCreate(BaseModel):
    """Payload for creating a new target."""

    value: str = Field(
        ...,
        min_length=1,
        max_length=512,
        description="The target identifier (domain, IP, email, etc.)",
    )
    type: str | None = Field(
        default=None,
        max_length=20,
        description="Target type. Auto-detected if not provided.",
    )
    priority: int = Field(
        default=0,
        ge=0,
        le=10,
        description="Priority 0-10, higher is more urgent",
    )


class TargetResponse(BaseModel):
    """Full target representation returned by the API."""

    id: int
    type: str
    value: str
    status: str
    priority: int
    metadata_: dict = Field(default_factory=dict)
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


class TargetListResponse(BaseModel):
    """Paginated list of targets."""

    items: list[TargetResponse]
    total: int
    page: int
    per_page: int
