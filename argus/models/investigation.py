"""
Argus OSINT – Investigation Model

An investigation groups one or more targets together with
classification, tags, and RBAC access control.
"""

from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import Column, DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.types import JSON

from argus.database import Base
from argus.models.target import Target, target_investigation


class Investigation(Base):
    """An OSINT investigation that groups multiple targets."""

    __tablename__ = "investigations"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)

    name: Mapped[str] = mapped_column(
        String(256),
        nullable=False,
        comment="Human-readable investigation name",
    )

    description: Mapped[str] = mapped_column(
        Text,
        nullable=False,
        default="",
        comment="Detailed description of the investigation scope and goals",
    )

    status: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
        default="active",
        index=True,
        comment="Investigation lifecycle status: active, closed, archived",
    )

    priority: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=0,
        comment="Priority level 0-5",
    )

    created_by: Mapped[int] = mapped_column(
        Integer,
        ForeignKey("users.id"),
        nullable=False,
        comment="User ID of the investigation creator",
    )

    tags: Mapped[list] = mapped_column(
        JSON,
        nullable=False,
        default=list,
        comment="List of string tags for categorisation",
    )

    classification: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
        default="TLP:CLEAR",
        comment="TLP classification: TLP:CLEAR, TLP:GREEN, TLP:AMBER, TLP:RED",
    )

    access_groups: Mapped[list] = mapped_column(
        JSON,
        nullable=False,
        default=list,
        comment="List of group names with access to this investigation (RBAC)",
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
    targets: Mapped[list[Target]] = relationship(
        "Target",
        secondary=target_investigation,
        back_populates="investigations",
        lazy="selectin",
    )

    def __repr__(self) -> str:
        return f"<Investigation id={self.id} name={self.name!r} status={self.status!r}>"
