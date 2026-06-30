"""
Argus OSINT – Targets API Router

CRUD operations for OSINT targets with auto-type classification,
pagination, filtering, and plugin scan triggering.
"""

from __future__ import annotations

import logging
import re
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from argus.database import get_db
from argus.models.plugin_result import PluginResult
from argus.models.target import Target
from argus.schemas.target import TargetCreate, TargetListResponse, TargetResponse
from argus.security.rbac import Permission, require_permission

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/targets", tags=["targets"])

# ── Auto-Classification ──────────────────────────────────────────────

_TYPE_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("domain", re.compile(r"^(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$")),
    ("ip", re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")),
    ("email", re.compile(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$")),
    ("url", re.compile(r"^https?://")),
    ("phone", re.compile(r"^\+?\d{7,15}$")),
    ("crypto", re.compile(r"^(?:0x[0-9a-fA-F]{40}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})$")),
]


def classify_target(value: str) -> str:
    """Auto-detect the target type from its value."""
    for target_type, pattern in _TYPE_PATTERNS:
        if pattern.match(value.strip()):
            return target_type
    return "unknown"


# ── Endpoints ───────────────────────────────────────────────────────

@router.post("/", response_model=TargetResponse, status_code=201)
async def create_target(
    payload: TargetCreate,
    db: AsyncSession = Depends(get_db),
    _auth: None = Depends(require_permission(Permission.TARGET_CREATE)),
) -> Target:
    """Create a new OSINT target, auto-classifying its type if not specified."""
    target_type = payload.type if payload.type else classify_target(payload.value)

    # Check for duplicates
    existing = await db.execute(
        select(Target).where(Target.value == payload.value.strip())
    )
    if existing.scalar_one_or_none() is not None:
        raise HTTPException(status_code=409, detail=f"Target '{payload.value}' already exists")

    target = Target(
        value=payload.value.strip(),
        type=target_type,
        priority=payload.priority,
    )
    db.add(target)
    await db.flush()
    await db.refresh(target)
    return target


@router.get("/", response_model=TargetListResponse)
async def list_targets(
    page: int = Query(default=1, ge=1),
    per_page: int = Query(default=20, ge=1, le=100),
    type: Optional[str] = Query(default=None, description="Filter by target type"),
    status: Optional[str] = Query(default=None, description="Filter by status"),
    search: Optional[str] = Query(default=None, description="Search in value"),
    db: AsyncSession = Depends(get_db),
    _auth: None = Depends(require_permission(Permission.TARGET_READ)),
) -> TargetListResponse:
    """List targets with pagination and optional filters."""
    query = select(Target)
    count_query = select(func.count(Target.id))

    if type is not None:
        query = query.where(Target.type == type)
        count_query = count_query.where(Target.type == type)
    if status is not None:
        query = query.where(Target.status == status)
        count_query = count_query.where(Target.status == status)
    if search is not None:
        search_term = f"%{search}%"
        query = query.where(Target.value.ilike(search_term))
        count_query = count_query.where(Target.value.ilike(search_term))

    total_result = await db.execute(count_query)
    total = total_result.scalar_one()

    offset = (page - 1) * per_page
    query = query.order_by(Target.created_at.desc()).offset(offset).limit(per_page)
    result = await db.execute(query)
    targets = result.scalars().all()

    return TargetListResponse(
        items=[TargetResponse.model_validate(t) for t in targets],
        total=total,
        page=page,
        per_page=per_page,
    )


@router.get("/{target_id}", response_model=TargetResponse)
async def get_target(
    target_id: int,
    db: AsyncSession = Depends(get_db),
    _auth: None = Depends(require_permission(Permission.TARGET_READ)),
) -> Target:
    """Retrieve a single target by ID."""
    result = await db.execute(select(Target).where(Target.id == target_id))
    target = result.scalar_one_or_none()
    if target is None:
        raise HTTPException(status_code=404, detail=f"Target {target_id} not found")
    return target


@router.delete("/{target_id}", status_code=204)
async def delete_target(
    target_id: int,
    db: AsyncSession = Depends(get_db),
    _auth: None = Depends(require_permission(Permission.TARGET_DELETE)),
) -> None:
    """Delete a target and all its associated plugin results."""
    result = await db.execute(select(Target).where(Target.id == target_id))
    target = result.scalar_one_or_none()
    if target is None:
        raise HTTPException(status_code=404, detail=f"Target {target_id} not found")

    await db.delete(target)
    await db.flush()


@router.post("/{target_id}/scan", response_model=dict)
async def scan_target(
    target_id: int,
    db: AsyncSession = Depends(get_db),
    _auth: None = Depends(require_permission(Permission.TARGET_SCAN)),
) -> dict:
    """Trigger a scan of all matching plugins against a target."""
    result = await db.execute(select(Target).where(Target.id == target_id))
    target = result.scalar_one_or_none()
    if target is None:
        raise HTTPException(status_code=404, detail=f"Target {target_id} not found")

    # Mark target as processing
    target.status = "processing"
    await db.flush()

    # Run all matching plugins
    from argus.plugins import run_all_for_target

    scan_results = await run_all_for_target(target.value, target.type)

    # Store results in database
    created_count = 0
    for sr in scan_results:
        plugin_name = sr.get("plugin_name", "unknown")
        plugin_result = PluginResult(
            target_id=target.id,
            plugin_name=plugin_name,
            status=sr["status"],
            data=sr["data"],
            execution_time=sr["execution_time"],
            cached=sr.get("cached", False),
            error_message=sr.get("error_message"),
        )
        db.add(plugin_result)
        created_count += 1

    # Update target status
    target.status = "completed"
    await db.flush()

    return {
        "target_id": target.id,
        "status": "scan_completed",
        "results_saved": created_count,
    }


@router.get("/{target_id}/results", response_model=list[dict])
async def get_target_results(
    target_id: int,
    db: AsyncSession = Depends(get_db),
    _auth: None = Depends(require_permission(Permission.TARGET_READ)),
) -> list[dict]:
    """Get all plugin execution results for a target."""
    result = await db.execute(select(Target).where(Target.id == target_id))
    target = result.scalar_one_or_none()
    if target is None:
        raise HTTPException(status_code=404, detail=f"Target {target_id} not found")

    results = await db.execute(
        select(PluginResult)
        .where(PluginResult.target_id == target_id)
        .order_by(PluginResult.created_at.desc())
    )
    plugin_results = results.scalars().all()

    return [
        {
            "id": pr.id,
            "plugin_name": pr.plugin_name,
            "status": pr.status,
            "execution_time": pr.execution_time,
            "cached": pr.cached,
            "error_message": pr.error_message,
            "data": pr.data,
            "created_at": pr.created_at.isoformat() if pr.created_at else None,
        }
        for pr in plugin_results
    ]
