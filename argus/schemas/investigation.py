"""
Argus OSINT – Investigation Schemas (Pydantic v2)

Request / response models for investigation CRUD and export operations.
"""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, Field


class InvestigationCreate(BaseModel):
    """Payload for creating a new investigation."""

    name: str = Field(
        ...,
        min_length=1,
        max_length=256,
        description="Investigation name",
    )
    description: str = Field(
        default="",
        max_length=4096,
        description="Detailed description of the investigation",
    )
    target_ids: list[int] = Field(
        default_factory=list,
        description="List of existing target IDs to attach",
    )
    tags: list[str] = Field(
        default_factory=list,
        description="Categorisation tags",
    )
    classification: str = Field(
        default="TLP:CLEAR",
        description="TLP classification level",
    )
    priority: int = Field(
        default=0,
        ge=0,
        le=5,
        description="Priority 0-5",
    )


class InvestigationUpdate(BaseModel):
    """Payload for updating an existing investigation."""

    name: str | None = Field(default=None, max_length=256)
    description: str | None = Field(default=None, max_length=4096)
    status: str | None = Field(
        default=None,
        description="active, closed, or archived",
    )
    priority: int | None = Field(default=None, ge=0, le=5)
    tags: list[str] | None = None
    classification: str | None = None
    access_groups: list[str] | None = None


class InvestigationResponse(BaseModel):
    """Full investigation representation returned by the API."""

    id: int
    name: str
    description: str
    status: str
    priority: int
    created_by: int
    tags: list[str] = Field(default_factory=list)
    classification: str
    access_groups: list[str] = Field(default_factory=list)
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


class InvestigationListResponse(BaseModel):
    """Paginated list of investigations."""

    items: list[InvestigationResponse]
    total: int
    page: int
