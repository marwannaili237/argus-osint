"""
Argus OSINT – User & API Key Models

User accounts with role-based access control, optional TOTP 2FA,
and per-user bot/settings preferences.  API keys allow programmatic
access with hashed storage and configurable rate limits.
"""

from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import Boolean, Column, DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.types import JSON

from argus.database import Base


class User(Base):
    """Application user with RBAC role and optional 2FA."""

    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)

    username: Mapped[str] = mapped_column(
        String(128),
        unique=True,
        index=True,
        nullable=False,
        comment="Unique login username",
    )

    email: Mapped[str] = mapped_column(
        String(256),
        unique=True,
        index=True,
        nullable=False,
        comment="Unique email address",
    )

    hashed_password: Mapped[str] = mapped_column(
        String(256),
        nullable=False,
        comment="bcrypt / argon2 hashed password",
    )

    is_active: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=True,
        comment="Whether the account is enabled",
    )

    is_superuser: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=False,
        comment="Full admin privileges override",
    )

    role: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
        default="analyst",
        index=True,
        comment="RBAC role: admin, analyst, viewer, auditor",
    )

    two_factor_secret: Mapped[str | None] = mapped_column(
        String(256),
        nullable=True,
        default=None,
        comment="TOTP shared secret (encrypted at rest)",
    )

    two_factor_enabled: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=False,
        comment="Whether TOTP 2FA is active",
    )

    preferred_language: Mapped[str] = mapped_column(
        String(10),
        nullable=False,
        default="en",
        comment="ISO 639-1 preferred language code",
    )

    settings: Mapped[dict] = mapped_column(
        JSON,
        nullable=False,
        default=dict,
        comment="Per-user bot/UI settings JSON blob",
    )

    last_login: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
        default=None,
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
    api_keys: Mapped[list["APIKey"]] = relationship(
        "APIKey",
        back_populates="user",
        lazy="selectin",
        cascade="all, delete-orphan",
    )

    def __repr__(self) -> str:
        return f"<User id={self.id} username={self.username!r} role={self.role!r}>"


class APIKey(Base):
    """API key for programmatic access with rate limiting."""

    __tablename__ = "api_keys"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)

    name: Mapped[str] = mapped_column(
        String(128),
        nullable=False,
        comment="Human-readable key label",
    )

    key_hash: Mapped[str] = mapped_column(
        String(256),
        unique=True,
        index=True,
        nullable=False,
        comment="SHA-256 hash of the raw API key (never stored raw)",
    )

    user_id: Mapped[int] = mapped_column(
        Integer,
        ForeignKey("users.id"),
        nullable=False,
        index=True,
    )

    is_active: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=True,
        comment="Whether this key is currently valid",
    )

    permissions: Mapped[list] = mapped_column(
        JSON,
        nullable=False,
        default=lambda: ["read"],
        comment="List of permission scopes, e.g. ['read', 'write', 'admin']",
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )

    last_used_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
        default=None,
    )

    expires_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
        default=None,
        comment="Optional key expiration timestamp",
    )

    rate_limit: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=100,
        comment="Maximum requests allowed per hour",
    )

    # ── Relationships ───────────────────────────────────────────────
    user: Mapped["User"] = relationship(
        "User",
        back_populates="api_keys",
    )

    def __repr__(self) -> str:
        return f"<APIKey id={self.id} name={self.name!r} user_id={self.user_id}>"
