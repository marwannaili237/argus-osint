"""
Argus OSINT – Security: Role-Based Access Control

Provides permission checks for users and API keys against
resource types and actions within the Argus OSINT platform.
"""

from __future__ import annotations

import logging
from enum import StrEnum
from typing import Any

from fastapi import Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from argus.database import get_db
from argus.models.user import APIKey, User

logger = logging.getLogger(__name__)


# ── Permission Definitions ────────────────────────────────────────────

class Permission(StrEnum):
    """Granular permission identifiers."""

    # Target operations
    TARGET_READ = "target:read"
    TARGET_CREATE = "target:create"
    TARGET_DELETE = "target:delete"
    TARGET_SCAN = "target:scan"

    # Investigation operations
    INVESTIGATION_READ = "investigation:read"
    INVESTIGATION_CREATE = "investigation:create"
    INVESTIGATION_UPDATE = "investigation:update"
    INVESTIGATION_DELETE = "investigation:delete"
    INVESTIGATION_EXPORT = "investigation:export"

    # Plugin operations
    PLUGIN_READ = "plugin:read"
    PLUGIN_EXECUTE = "plugin:execute"

    # User operations
    USER_READ = "user:read"
    USER_CREATE = "user:create"
    USER_UPDATE = "user:update"
    USER_DELETE = "user:delete"
    USER_ADMIN = "user:admin"

    # API key operations
    APIKEY_CREATE = "apikey:create"
    APIKEY_DELETE = "apikey:delete"

    # Dashboard
    DASHBOARD_READ = "dashboard:read"


# ── Role → Permission Mapping ────────────────────────────────────────

ROLE_PERMISSIONS: dict[str, set[Permission]] = {
    "admin": set(Permission),  # Full access
    "analyst": {
        Permission.TARGET_READ,
        Permission.TARGET_CREATE,
        Permission.TARGET_DELETE,
        Permission.TARGET_SCAN,
        Permission.INVESTIGATION_READ,
        Permission.INVESTIGATION_CREATE,
        Permission.INVESTIGATION_UPDATE,
        Permission.INVESTIGATION_EXPORT,
        Permission.PLUGIN_READ,
        Permission.PLUGIN_EXECUTE,
        Permission.APIKEY_CREATE,
        Permission.APIKEY_DELETE,
        Permission.DASHBOARD_READ,
    },
    "viewer": {
        Permission.TARGET_READ,
        Permission.INVESTIGATION_READ,
        Permission.PLUGIN_READ,
        Permission.DASHBOARD_READ,
    },
    "auditor": {
        Permission.TARGET_READ,
        Permission.INVESTIGATION_READ,
        Permission.USER_READ,
        Permission.PLUGIN_READ,
        Permission.DASHBOARD_READ,
    },
}


def has_permission(user_role: str, permission: Permission) -> bool:
    """Check whether a given role grants a specific permission."""
    return permission in ROLE_PERMISSIONS.get(user_role, set())


def has_any_permission(user_role: str, permissions: set[Permission]) -> bool:
    """Check whether a role grants any of the listed permissions."""
    role_perms = ROLE_PERMISSIONS.get(user_role, set())
    return bool(role_perms & permissions)


def require_permission(permission: Permission):
    """FastAPI dependency that asserts the authenticated user has a permission.

    Usage:
        @router.post("/targets/")
        async def create_target(
            ...,
            _auth: None = Depends(require_permission(Permission.TARGET_CREATE)),
        ):
            ...
    """
    async def checker(request: Request, db: AsyncSession = Depends(get_db)) -> None:
        user = request.state.current_user

        if user is None:
            # Try API key authentication
            api_key: APIKey | None = getattr(request.state, "current_api_key", None)
            if api_key is None:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Authentication required",
                )
            # API key permissions check
            key_perms = {p.lower() for p in api_key.permissions}
            if permission.value not in key_perms and "admin" not in key_perms:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"API key lacks permission: {permission.value}",
                )
            return

        if not has_permission(user.role, permission):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Role '{user.role}' lacks permission: {permission.value}",
            )

    return checker


def require_role(*roles: str):
    """FastAPI dependency that asserts the authenticated user has one of the listed roles."""
    async def checker(request: Request) -> None:
        user: User | None = getattr(request.state, "current_user", None)
        if user is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Authentication required",
            )
        if user.role not in roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Requires one of roles: {', '.join(roles)}",
            )

    return checker


def check_investigation_access(
    user: User | None,
    investigation: Any,
    required_permission: Permission = Permission.INVESTIGATION_READ,
) -> bool:
    """Check if a user can access a specific investigation.

    Admins and superusers bypass all checks.
    Otherwise the user must have the required permission AND
    the investigation's access_groups must include one of the user's groups
    or be empty (open access).
    """
    if user is None:
        return False

    if user.is_superuser or user.role == "admin":
        return True

    if not has_permission(user.role, required_permission):
        return False

    access_groups: list[str] = getattr(investigation, "access_groups", [])
    if not access_groups:
        return True  # Open investigation

    # Check if user's settings contain any matching group
    user_groups: list[str] = getattr(user, "settings", {}).get("groups", [])
    if not user_groups and user.role == "analyst":
        return True  # Analysts default to access if no groups configured

    return bool(set(access_groups) & set(user_groups))
