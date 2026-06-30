"""
Argus OSINT – Target Model

Represents an OSINT target (domain, IP, email, username, etc.)
with its classification, status, and plugin execution results.
"""

from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import Column, DateTime, Float, Integer, String, Table, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.types import JSON

from argus.database import Base

# ── Association Table ────────────────────────────────────────────────
target_investigation = Table(
    "target_investigation",
    Base.metadata,
    Column("target_id", Integer, primary_key=True),
    Column("investigation_id", Integer, primary_key=True),
)


class Target(Base):
    """An OSINT reconnaissance target."""

    __tablename__ = "targets"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)

    type: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
        index=True,
        comment="Target type: domain, url, ip, email, username, phone, image, person, company, crypto, unknown",
    )

    value: Mapped[str] = mapped_column(
        String(512),
        unique=True,
        index=True,
        nullable=False,
        comment="The target identifier value (e.g. example.com, 1.2.3.4)",
    )

    status: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
        default="pending",
        index=True,
        comment="Current status: pending, processing, completed, failed",
    )

    priority: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=0,
        comment="Priority 0-10, higher means more urgent",
    )

    metadata_: Mapped[dict] = mapped_column(
        JSON,
        nullable=False,
        default=dict,
        comment="Arbitrary metadata about the target",
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )

    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
    )

    # ── Relationships ───────────────────────────────────────────────
    investigations: Mapped[list["Investigation"]] = relationship(
        "Investigation",
        secondary=target_investigation,
        back_populates="targets",
        lazy="selectin",
    )

    plugin_results: Mapped[list["PluginResult"]] = relationship(
        "PluginResult",
        back_populates="target",
        lazy="selectin",
        cascade="all, delete-orphan",
    )

    def __repr__(self) -> str:
        return f"<Target id={self.id} type={self.type!r} value={self.value!r} status={self.status!r}>"
