"""
Argus OSINT – Plugin Result Model

Stores the output of each plugin execution against a target,
including timing, caching status, and any error details.
"""

from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import Boolean, Column, DateTime, Float, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.types import JSON

from argus.database import Base


class PluginResult(Base):
    """Result of executing a single plugin against a target."""

    __tablename__ = "plugin_results"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)

    target_id: Mapped[int] = mapped_column(
        Integer,
        ForeignKey("targets.id"),
        nullable=False,
        index=True,
        comment="The target this result belongs to",
    )

    plugin_name: Mapped[str] = mapped_column(
        String(128),
        nullable=False,
        index=True,
        comment="Machine-readable plugin identifier",
    )

    status: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
        default="success",
        index=True,
        comment="Execution status: success, error, timeout, cached",
    )

    data: Mapped[dict] = mapped_column(
        JSON,
        nullable=False,
        default=dict,
        comment="Plugin output data payload",
    )

    execution_time: Mapped[float] = mapped_column(
        Float,
        nullable=False,
        default=0.0,
        comment="Wall-clock execution time in seconds",
    )

    cached: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=False,
        comment="Whether this result was served from cache",
    )

    error_message: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
        default=None,
        comment="Error details if status is 'error' or 'timeout'",
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )

    # ── Relationships ───────────────────────────────────────────────
    target: Mapped["Target"] = relationship(
        "Target",
        back_populates="plugin_results",
    )

    def __repr__(self) -> str:
        return f"<PluginResult id={self.id} plugin={self.plugin_name!r} target_id={self.target_id} status={self.status!r}>"
