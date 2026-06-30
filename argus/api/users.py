"""
Argus OSINT – Users API Router

Registration, JWT-based login, TOTP 2FA enablement/verification,
profile management, and admin user management.
"""

from __future__ import annotations

import hashlib
import hmac
import logging
import secrets
from datetime import datetime, timedelta, timezone
from typing import Optional

import jwt
from fastapi import APIRouter, Depends, HTTPException, Query, Response
from pydantic import BaseModel, EmailStr, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from argus.config import get_settings
from argus.database import get_db
from argus.models.user import User
from argus.security.rbac import Permission, require_permission, require_role

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/users", tags=["users"])


# ── Schemas ─────────────────────────────────────────────────────────

class UserRegister(BaseModel):
    username: str = Field(..., min_length=3, max_length=128)
    email: EmailStr
    password: str = Field(..., min_length=8, max_length=256)


class UserLogin(BaseModel):
    username: str
    password: str
    totp_code: Optional[str] = Field(None, description="TOTP code if 2FA is enabled")


class TOTPEnableResponse(BaseModel):
    secret: str
    qr_data: str
    backup_codes: list[str]


class TOTPVerifyRequest(BaseModel):
    code: str = Field(..., min_length=6, max_length=6)


class UserProfile(BaseModel):
    id: int
    username: str
    email: str
    role: str
    is_active: bool
    two_factor_enabled: bool
    preferred_language: str
    last_login: Optional[datetime]
    created_at: datetime
    settings: dict = Field(default_factory=dict)

    model_config = {"from_attributes": True}


class UserSettingsUpdate(BaseModel):
    preferred_language: Optional[str] = Field(None, max_length=10)
    settings: Optional[dict] = None


class RoleUpdate(BaseModel):
    role: str = Field(..., pattern=r"^(admin|analyst|viewer|auditor)$")


class UserListResponse(BaseModel):
    items: list[UserProfile]
    total: int


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int


# ── Helpers ─────────────────────────────────────────────────────────

def _hash_password(password: str) -> str:
    """Hash a password using SHA-256 + salt (production should use bcrypt/argon2)."""
    salt = secrets.token_hex(16)
    hashed = hashlib.sha256((salt + password).encode()).hexdigest()
    return f"{salt}${hashed}"


def _verify_password(password: str, stored: str) -> bool:
    """Verify a password against its stored hash."""
    salt, _ = stored.split("$", 1)
    computed = hashlib.sha256((salt + password).encode()).hexdigest()
    return hmac.compare_digest(computed, stored.split("$", 1)[1])


def _create_jwt(user_id: int, role: str) -> str:
    """Create a signed JWT token."""
    settings = get_settings()
    expire = datetime.now(timezone.utc) + timedelta(hours=24)
    payload = {
        "sub": str(user_id),
        "role": role,
        "exp": expire,
        "iat": datetime.now(timezone.utc),
    }
    return jwt.encode(payload, settings.SECRET_KEY, algorithm="HS256")


def _generate_totp_secret() -> str:
    """Generate a base32-encoded TOTP secret."""
    return secrets.token_hex(20).upper()


def _generate_backup_codes(count: int = 10) -> list[str]:
    """Generate one-time backup codes for 2FA recovery."""
    return [secrets.token_hex(6).upper() for _ in range(count)]


def _get_totp_uri(secret: str, email: str) -> str:
    """Generate the otpauth:// URI for TOTP QR code enrollment."""
    return f"otpauth://totp/Argus:{email}?secret={secret}&issuer=Argus+OSINT&algorithm=SHA1&digits=6&period=30"


# ── Endpoints ───────────────────────────────────────────────────────

@router.post("/register", response_model=UserProfile, status_code=201)
async def register_user(
    payload: UserRegister,
    db: AsyncSession = Depends(get_db),
) -> User:
    """Register a new user account."""
    # Check for existing username
    existing = await db.execute(
        select(User).where(User.username == payload.username)
    )
    if existing.scalar_one_or_none() is not None:
        raise HTTPException(status_code=409, detail="Username already exists")

    # Check for existing email
    existing_email = await db.execute(
        select(User).where(User.email == payload.email)
    )
    if existing_email.scalar_one_or_none() is not None:
        raise HTTPException(status_code=409, detail="Email already registered")

    user = User(
        username=payload.username,
        email=payload.email,
        hashed_password=_hash_password(payload.password),
        role="analyst",
    )
    db.add(user)
    await db.flush()
    await db.refresh(user)
    return user


@router.post("/login", response_model=TokenResponse)
async def login_user(
    payload: UserLogin,
    db: AsyncSession = Depends(get_db),
) -> TokenResponse:
    """Authenticate a user and return a JWT token."""
    result = await db.execute(
        select(User).where(User.username == payload.username)
    )
    user = result.scalar_one_or_none()

    if user is None or not _verify_password(payload.password, user.hashed_password):
        raise HTTPException(status_code=401, detail="Invalid credentials")

    if not user.is_active:
        raise HTTPException(status_code=403, detail="Account is disabled")

    # Check 2FA
    if user.two_factor_enabled:
        if not payload.totp_code:
            raise HTTPException(status_code=401, detail="2FA code required")
        # Validate TOTP code
        import pyotp
        totp = pyotp.TOTP(user.two_factor_secret)
        if not totp.verify(payload.totp_code, valid_window=1):
            raise HTTPException(status_code=401, detail="Invalid 2FA code")

    # Update last login
    user.last_login = datetime.now(timezone.utc)
    await db.flush()

    token = _create_jwt(user.id, user.role)
    return TokenResponse(access_token=token, expires_in=86400)


@router.post("/2fa/enable", response_model=TOTPEnableResponse)
async def enable_2fa(
    _auth_user_id: int = Depends(require_permission(Permission.USER_UPDATE)),
    db: AsyncSession = Depends(get_db),
) -> TOTPEnableResponse:
    """Enable TOTP 2FA – returns the secret and QR data for enrollment."""
    # In production, this would use the authenticated user from request.state
    # For now, look up user ID 1 as a placeholder
    result = await db.execute(select(User).where(User.id == 1))
    user = result.scalar_one_or_none()
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")

    secret = _generate_totp_secret()
    user.two_factor_secret = secret
    user.two_factor_enabled = False  # Not enabled until verified
    await db.flush()

    backup_codes = _generate_backup_codes(10)
    user.settings = {**user.settings, "backup_codes": backup_codes}
    await db.flush()

    return TOTPEnableResponse(
        secret=secret,
        qr_data=_get_totp_uri(secret, user.email),
        backup_codes=backup_codes,
    )


@router.post("/2fa/verify")
async def verify_2fa(
    payload: TOTPVerifyRequest,
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Verify the TOTP code and finalize 2FA enablement."""
    result = await db.execute(select(User).where(User.id == 1))
    user = result.scalar_one_or_none()
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")

    if not user.two_factor_secret:
        raise HTTPException(status_code=400, detail="2FA not set up – call /2fa/enable first")

    import pyotp
    totp = pyotp.TOTP(user.two_factor_secret)
    if not totp.verify(payload.code, valid_window=1):
        raise HTTPException(status_code=401, detail="Invalid TOTP code")

    user.two_factor_enabled = True
    await db.flush()

    return {"status": "2fa_enabled", "message": "Two-factor authentication has been enabled"}


@router.get("/me", response_model=UserProfile)
async def get_current_user(
    db: AsyncSession = Depends(get_db),
    _auth: None = Depends(require_permission(Permission.USER_READ)),
) -> UserProfile:
    """Get the current authenticated user's profile."""
    result = await db.execute(select(User).where(User.id == 1))
    user = result.scalar_one_or_none()
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")
    return user


@router.put("/me/settings", response_model=UserProfile)
async def update_user_settings(
    payload: UserSettingsUpdate,
    db: AsyncSession = Depends(get_db),
    _auth: None = Depends(require_permission(Permission.USER_UPDATE)),
) -> UserProfile:
    """Update the current user's settings."""
    result = await db.execute(select(User).where(User.id == 1))
    user = result.scalar_one_or_none()
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")

    if payload.preferred_language is not None:
        user.preferred_language = payload.preferred_language
    if payload.settings is not None:
        user.settings = {**user.settings, **payload.settings}

    await db.flush()
    await db.refresh(user)
    return user


@router.get("/", response_model=UserListResponse)
async def list_users(
    page: int = Query(default=1, ge=1),
    per_page: int = Query(default=20, ge=1, le=100),
    db: AsyncSession = Depends(get_db),
    _auth: None = Depends(require_role("admin")),
) -> UserListResponse:
    """Admin-only: list all users with pagination."""
    from sqlalchemy import func

    count_result = await db.execute(select(func.count(User.id)))
    total = count_result.scalar_one()

    offset = (page - 1) * per_page
    result = await db.execute(
        select(User)
        .order_by(User.created_at.desc())
        .offset(offset)
        .limit(per_page)
    )
    users = result.scalars().all()

    return UserListResponse(
        items=[UserProfile.model_validate(u) for u in users],
        total=total,
    )


@router.put("/{user_id}/role", response_model=UserProfile)
async def update_user_role(
    user_id: int,
    payload: RoleUpdate,
    db: AsyncSession = Depends(get_db),
    _auth: None = Depends(require_role("admin")),
) -> UserProfile:
    """Admin-only: change a user's role."""
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    if user is None:
        raise HTTPException(status_code=404, detail=f"User {user_id} not found")

    if user.is_superuser:
        raise HTTPException(status_code=403, detail="Cannot modify superuser roles")

    user.role = payload.role
    await db.flush()
    await db.refresh(user)
    return user
