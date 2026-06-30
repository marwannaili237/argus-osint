"""
Argus OSINT – Dashboard API Router

Provides aggregate statistics, activity timeline, threat distribution,
network graph data (for D3.js), and geolocation data (for Leaflet).
"""

from __future__ import annotations

import logging
from collections import defaultdict
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, Query
from sqlalchemy import func, select, case
from sqlalchemy.ext.asyncio import AsyncSession

from argus.database import get_db
from argus.models.investigation import Investigation
from argus.models.plugin_result import PluginResult
from argus.models.target import Target
from argus.security.rbac import Permission, require_permission

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/dashboard", tags=["dashboard"])


@router.get("/stats")
async def get_dashboard_stats(
    db: AsyncSession = Depends(get_db),
    _auth: None = Depends(require_permission(Permission.DASHBOARD_READ)),
) -> dict:
    """Overall platform statistics."""
    # Total targets
    target_count = await db.execute(select(func.count(Target.id)))
    total_targets = target_count.scalar_one()

    # Total investigations
    inv_count = await db.execute(select(func.count(Investigation.id)))
    total_investigations = inv_count.scalar_one()

    # Total plugin results
    result_count = await db.execute(select(func.count(PluginResult.id)))
    total_results = result_count.scalar_one()

    # Target status distribution
    status_dist = await db.execute(
        select(Target.status, func.count(Target.id))
        .group_by(Target.status)
    )
    target_statuses = {row[0]: row[1] for row in status_dist.all()}

    # Target type distribution
    type_dist = await db.execute(
        select(Target.type, func.count(Target.id))
        .group_by(Target.type)
    )
    target_types = {row[0]: row[1] for row in type_dist.all()}

    # Investigation status distribution
    inv_status_dist = await db.execute(
        select(Investigation.status, func.count(Investigation.id))
        .group_by(Investigation.status)
    )
    investigation_statuses = {row[0]: row[1] for row in inv_status_dist.all()}

    # Plugin results by status
    pr_status_dist = await db.execute(
        select(PluginResult.status, func.count(PluginResult.id))
        .group_by(PluginResult.status)
    )
    result_statuses = {row[0]: row[1] for row in pr_status_dist.all()}

    # Threat level estimation based on results
    threat_high = result_statuses.get("error", 0)
    threat_medium = target_statuses.get("processing", 0)
    threat_low = target_statuses.get("completed", 0)

    return {
        "total_targets": total_targets,
        "total_investigations": total_investigations,
        "total_results": total_results,
        "target_statuses": target_statuses,
        "target_types": target_types,
        "investigation_statuses": investigation_statuses,
        "result_statuses": result_statuses,
        "threat_levels": {
            "high": threat_high,
            "medium": threat_medium,
            "low": threat_low,
        },
    }


@router.get("/timeline")
async def get_activity_timeline(
    limit: int = Query(default=50, ge=1, le=200),
    db: AsyncSession = Depends(get_db),
    _auth: None = Depends(require_permission(Permission.DASHBOARD_READ)),
) -> list[dict]:
    """Recent activity timeline combining targets, investigations, and results."""
    timeline: list[dict] = []

    # Recent targets
    targets_result = await db.execute(
        select(Target)
        .order_by(Target.created_at.desc())
        .limit(limit)
    )
    for t in targets_result.scalars().all():
        timeline.append({
            "type": "target_created",
            "id": t.id,
            "label": t.value,
            "detail": f"Type: {t.type}, Status: {t.status}",
            "timestamp": t.created_at.isoformat() if t.created_at else None,
        })

    # Recent investigations
    inv_result = await db.execute(
        select(Investigation)
        .order_by(Investigation.created_at.desc())
        .limit(limit)
    )
    for inv in inv_result.scalars().all():
        timeline.append({
            "type": "investigation_created",
            "id": inv.id,
            "label": inv.name,
            "detail": f"Classification: {inv.classification}, Priority: {inv.priority}",
            "timestamp": inv.created_at.isoformat() if inv.created_at else None,
        })

    # Recent plugin results
    pr_result = await db.execute(
        select(PluginResult)
        .order_by(PluginResult.created_at.desc())
        .limit(limit)
    )
    for pr in pr_result.scalars().all():
        timeline.append({
            "type": "plugin_executed",
            "id": pr.id,
            "label": pr.plugin_name,
            "detail": f"Target ID: {pr.target_id}, Status: {pr.status}",
            "timestamp": pr.created_at.isoformat() if pr.created_at else None,
        })

    # Sort by timestamp descending
    timeline.sort(key=lambda x: x["timestamp"] or "", reverse=True)
    return timeline[:limit]


@router.get("/threats")
async def get_threat_distribution(
    db: AsyncSession = Depends(get_db),
    _auth: None = Depends(require_permission(Permission.DASHBOARD_READ)),
) -> dict:
    """Threat distribution across targets and plugin results."""
    # Count targets with errors vs success
    error_count_result = await db.execute(
        select(func.count(PluginResult.id)).where(PluginResult.status == "error")
    )
    error_count = error_count_result.scalar_one() or 0

    timeout_count_result = await db.execute(
        select(func.count(PluginResult.id)).where(PluginResult.status == "timeout")
    )
    timeout_count = timeout_count_result.scalar_one() or 0

    success_count_result = await db.execute(
        select(func.count(PluginResult.id)).where(PluginResult.status == "success")
    )
    success_count = success_count_result.scalar_one() or 0

    cached_count_result = await db.execute(
        select(func.count(PluginResult.id)).where(PluginResult.status == "cached")
    )
    cached_count = cached_count_result.scalar_one() or 0

    # Plugin breakdown
    plugin_dist = await db.execute(
        select(PluginResult.plugin_name, func.count(PluginResult.id))
        .group_by(PluginResult.plugin_name)
        .order_by(func.count(PluginResult.id).desc())
    )
    plugin_breakdown = {row[0]: row[1] for row in plugin_dist.all()}

    # Target classification breakdown
    classification_dist = await db.execute(
        select(Investigation.classification, func.count(Investigation.id))
        .group_by(Investigation.classification)
    )
    classification_breakdown = {row[0]: row[1] for row in classification_dist.all()}

    return {
        "plugin_results_by_status": {
            "success": success_count,
            "error": error_count,
            "timeout": timeout_count,
            "cached": cached_count,
        },
        "plugin_breakdown": plugin_breakdown,
        "classification_breakdown": classification_breakdown,
    }


@router.get("/network")
async def get_network_graph_data(
    limit: int = Query(default=100, ge=1, le=500),
    db: AsyncSession = Depends(get_db),
    _auth: None = Depends(require_permission(Permission.DASHBOARD_READ)),
) -> dict:
    """Network graph data for D3.js force-directed visualization.

    Returns nodes (targets, investigations, plugins) and edges (relationships).
    """
    nodes: list[dict] = []
    edges: list[dict] = []
    node_ids: set[str] = set()

    def _add_node(node_id: str, node_type: str, label: str, **extra: object) -> None:
        if node_id not in node_ids:
            node_ids.add(node_id)
            entry: dict = {
                "id": node_id,
                "type": node_type,
                "label": label,
            }
            entry.update(extra)
            nodes.append(entry)

    # Investigation nodes
    inv_result = await db.execute(
        select(Investigation).limit(limit)
    )
    for inv in inv_result.scalars().all():
        _add_node(f"inv_{inv.id}", "investigation", inv.name,
                   status=inv.status, classification=inv.classification)

    # Target nodes
    target_result = await db.execute(
        select(Target).limit(limit)
    )
    for t in target_result.scalars().all():
        _add_node(f"target_{t.id}", t.type, t.value,
                   status=t.status, priority=t.priority)

    # Plugin result nodes and edges
    pr_result = await db.execute(
        select(PluginResult).limit(limit)
    )
    for pr in pr_result.scalars().all():
        _add_node(f"plugin_{pr.plugin_name}", "plugin", pr.plugin_name)
        edges.append({
            "source": f"target_{pr.target_id}",
            "target": f"plugin_{pr.plugin_name}",
            "status": pr.status,
            "execution_time": pr.execution_time,
        })

    # Investigation → Target edges
    from argus.models.target import target_investigation
    link_result = await db.execute(
        select(
            target_investigation.c.investigation_id,
            target_investigation.c.target_id,
        ).limit(limit)
    )
    for inv_id, target_id in link_result.all():
        edges.append({
            "source": f"inv_{inv_id}",
            "target": f"target_{target_id}",
            "type": "contains",
        })

    return {
        "nodes": nodes,
        "edges": edges,
        "total_nodes": len(nodes),
        "total_edges": len(edges),
    }


@router.get("/geolocation")
async def get_geolocation_data(
    db: AsyncSession = Depends(get_db),
    _auth: None = Depends(require_permission(Permission.DASHBOARD_READ)),
) -> dict:
    """Geolocation data for Leaflet map visualization.

    Extracts location data from plugin results that contain
    geographic coordinates or location information.
    """
    # Get plugin results that have geo data in their JSON payload
    pr_result = await db.execute(
        select(PluginResult, Target.value, Target.type)
        .join(Target, PluginResult.target_id == Target.id)
        .order_by(PluginResult.created_at.desc())
        .limit(500)
    )

    locations: list[dict] = []
    for pr, target_value, target_type in pr_result.all():
        data = pr.data or {}
        geo = data.get("geo") or data.get("geolocation") or data.get("location")

        if isinstance(geo, dict):
            lat = geo.get("lat") or geo.get("latitude")
            lon = geo.get("lon") or geo.get("lng") or geo.get("longitude")
            if lat is not None and lon is not None:
                locations.append({
                    "target_id": pr.target_id,
                    "target_value": target_value,
                    "target_type": target_type,
                    "plugin": pr.plugin_name,
                    "lat": float(lat),
                    "lon": float(lon),
                    "city": geo.get("city") or geo.get("city_name"),
                    "country": geo.get("country") or geo.get("country_name"),
                    "org": geo.get("org") or geo.get("organization"),
                    "label": f"{target_value}\n{geo.get('city', '')}, {geo.get('country', '')}".strip(),
                })
            continue

        # Some plugins store coords at the top level
        if isinstance(data, dict):
            lat = data.get("lat") or data.get("latitude")
            lon = data.get("lon") or data.get("lng") or data.get("longitude")
            if lat is not None and lon is not None:
                locations.append({
                    "target_id": pr.target_id,
                    "target_value": target_value,
                    "target_type": target_type,
                    "plugin": pr.plugin_name,
                    "lat": float(lat),
                    "lon": float(lon),
                    "city": data.get("city"),
                    "country": data.get("country"),
                    "org": data.get("org"),
                    "label": f"{target_value}\n{data.get('city', '')}, {data.get('country', '')}".strip(),
                })

    return {
        "locations": locations,
        "total": len(locations),
    }
