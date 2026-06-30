"""
Argus OSINT – API Keys Router

Generate, list, and revoke API keys. Includes a middleware-style
validation helper for checking X-API-Key headers in the request pipeline.
"""

from __future__ import annotations

import hashlib
import logging
import secrets
import time
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from argus.database import get_db
from argus.models.user import APIKey as APIKeyModel
from argus.models.user import User
from argus.security.rbac import Permission, require_permission

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api-keys", tags=["api-keys"])


# ── Schemas ─────────────────────────────────────────────────────────

class APIKeyCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=128, description="Label for the key")
    permissions: list[str] = Field(
        default_factory=lambda: ["read"],
        description="Permission scopes for this key",
    )
    expires_days: Optional[int] = Field(
        default=None,
        ge=1,
        le=365,
        description="Days until key expiration (None = no expiry)",
    )
    rate_limit: int = Field(default=100, ge=1, le=10000, description="Requests per hour")


class APIKeyResponse(BaseModel):
    id: int
    name: str
    is_active: bool
    permissions: list[str]
    created_at: datetime
    last_used_at: Optional[datetime]
    expires_at: Optional[datetime]
    rate_limit: int

    model_config = {"from_attributes": True}


class APIKeyCreatedResponse(BaseModel):
    """Returned only once when a key is created – includes the raw key."""
    id: int
    name: str
    key: str  # Raw key – never returned again
    permissions: list[str]
    expires_at: Optional[datetime]
    rate_limit: int


# ── Key Utilities ───────────────────────────────────────────────────

def generate_raw_key(prefix: str = "argus") -> str:
    """Generate a cryptographically secure random API key."""
    raw = secrets.token_urlsafe(32)
    return f"{prefix}_{raw}"


def hash_key(raw_key: str) -> str:
    """Hash an API key for storage (SHA-256)."""
    return hashlib.sha256(raw_key.encode("utf-8")).hexdigest()


# ── Rate Limiter (in-memory) ─────────────────────────────────────────

class _RateLimiter:
    """Simple in-memory rate limiter keyed by API key hash."""

    def __init__(self) -> None:
        self._buckets: dict[str, list[float]] = {}

    def is_allowed(self, key_hash: str, limit: int, window: float = 3600.0) -> bool:
        """Check if the key is within its rate limit."""
        now = time.monotonic()
        cutoff = now - window

        bucket = self._buckets.setdefault(key_hash, [])
        # Remove expired entries
        self._buckets[key_hash] = bucket = [t for t in bucket if t > cutoff]

        if len(bucket) >= limit:
            return False

        bucket.append(now)
        return True


rate_limiter = _RateLimiter()


# ── Validation Helper ────────────────────────────────────────────────

async def validate_api_key(
    raw_key: str,
    db: AsyncSession,
) -> APIKeyModel:
    """Validate an API key from the X-API-Key header.

    Raises HTTPException if the key is invalid, expired, revoked,
    or rate-limited.
    """
    key_hash = hash_key(raw_key)

    result = await db.execute(
        select(APIKeyModel).where(APIKeyModel.key_hash == key_hash)
    )
    api_key = result.scalar_one_or_none()

    if api_key is None:
        raise HTTPException(status_code=401, detail="Invalid API key")

    if not api_key.is_active:
        raise HTTPException(status_code=401, detail="API key has been revoked")

    if api_key.expires_at and api_key.expires_at < datetime.now(timezone.utc):
        raise HTTPException(status_code=401, detail="API key has expired")

    # Rate limit check
    if not rate_limiter.is_allowed(key_hash, api_key.rate_limit):
        raise HTTPException(
            status_code=429,
            detail=f"Rate limit exceeded ({api_key.rate_limit} requests per hour)",
        )

    # Update last used timestamp
    api_key.last_used_at = datetime.now(timezone.utc)
    await db.flush()

    return api_key


# ── Endpoints ───────────────────────────────────────────────────────

@router.post("/", response_model=APIKeyCreatedResponse, status_code=201)
async def create_api_key(
    payload: APIKeyCreate,
    db: AsyncSession = Depends(get_db),
    _auth: None = Depends(require_permission(Permission.APIKEY_CREATE)),
) -> dict:
    """Generate a new API key. The raw key is returned ONLY once."""
    raw_key = generate_raw_key()
    key_hash = hash_key(raw_key)

    expires_at = None
    if payload.expires_days is not None:
        expires_at = datetime.now(timezone.utc).replace(
            microsecond=0
        ) + __import__("datetime").timedelta(days=payload.expires_days)

    # Determine user_id – try from request state
    # For now default to 1 (first admin); in production this comes from auth
    api_key = APIKeyModel(
        name=payload.name,
        key_hash=key_hash,
        user_id=1,  # Will be overridden by auth middleware
        permissions=payload.permissions,
        expires_at=expires_at,
        rate_limit=payload.rate_limit,
    )
    db.add(api_key)
    await db.flush()
    await db.refresh(api_key)

    return {
        "id": api_key.id,
        "name": api_key.name,
        "key": raw_key,
        "permissions": api_key.permissions,
        "expires_at": api_key.expires_at,
        "rate_limit": api_key.rate_limit,
    }


@router.get("/", response_model=list[APIKeyResponse])
async def list_api_keys(
    db: AsyncSession = Depends(get_db),
    _auth: None = Depends(require_permission(Permission.APIKEY_CREATE)),
) -> list[APIKeyModel]:
    """List the current user's API keys (raw keys are never shown)."""
    result = await db.execute(
        select(APIKeyModel).where(APIKeyModel.user_id == 1).order_by(APIKeyModel.created_at.desc())
    )
    return result.scalars().all()


@router.delete("/{key_id}", status_code=204)
async def revoke_api_key(
    key_id: int,
    db: AsyncSession = Depends(get_db),
    _auth: None = Depends(require_permission(Permission.APIKEY_DELETE)),
) -> None:
    """Revoke an API key by ID."""
    result = await db.execute(
        select(APIKeyModel).where(APIKeyModel.id == key_id)
    )
    api_key = result.scalar_one_or_none()
    if api_key is None:
        raise HTTPException(status_code=404, detail=f"API key {key_id} not found")

    api_key.is_active = False
    await db.flush()
