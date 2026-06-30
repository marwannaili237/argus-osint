"""
Argus OSINT – Plugins API Router

Plugin management: list registered plugins, check health, and
manually trigger plugin execution against targets.
"""

from __future__ import annotations

import logging
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from argus.database import get_db
from argus.models.target import Target
from argus.plugins import registry, run_plugin
from argus.security.rbac import Permission, require_permission

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/plugins", tags=["plugins"])


# ── Schemas ─────────────────────────────────────────────────────────

class PluginRunRequest(BaseModel):
    """Request body for manually running a plugin."""

    target_value: str = Field(..., description="Target to run the plugin against")
    target_type: Optional[str] = Field(None, description="Override target type auto-detection")
    timeout: float = Field(default=30.0, ge=1.0, le=300.0, description="Execution timeout in seconds")


# ── Endpoints ───────────────────────────────────────────────────────

@router.get("/")
async def list_plugins(
    target_type: Optional[str] = Query(default=None, description="Filter by supported target type"),
    _auth: None = Depends(require_permission(Permission.PLUGIN_READ)),
) -> dict:
    """List all registered plugins, optionally filtered by target type."""
    grouped = registry.grouped_by_type()

    if target_type is not None:
        plugins = registry.by_target_type(target_type)
        plugins_info = [
            {
                "name": p.info.name,
                "display_name": p.info.display_name,
                "description": p.info.description,
                "version": p.info.version,
                "supported_types": p.info.supported_types,
                "tags": p.info.tags,
                "requires_api_key": p.info.requires_api_key,
            }
            for p in plugins
        ]
        return {"target_type": target_type, "plugins": plugins_info, "count": len(plugins_info)}

    result = {}
    for t, infos in grouped.items():
        result[t] = [
            {
                "name": info.name,
                "display_name": info.display_name,
                "description": info.description,
                "version": info.version,
                "supported_types": info.supported_types,
                "tags": info.tags,
                "requires_api_key": info.requires_api_key,
            }
            for info in infos
        ]

    return {"groups": result, "total": registry.count}


@router.get("/{plugin_name}/health")
async def plugin_health(
    plugin_name: str,
    _auth: None = Depends(require_permission(Permission.PLUGIN_READ)),
) -> dict:
    """Get the health status of a specific plugin."""
    plugin = registry.get(plugin_name)
    if plugin is None:
        raise HTTPException(status_code=404, detail=f"Plugin '{plugin_name}' not found")

    return {
        "name": plugin.info.name,
        "display_name": plugin.info.display_name,
        "status": "registered",
        "version": plugin.info.version,
        "supported_types": plugin.info.supported_types,
    }


@router.post("/{plugin_name}/run")
async def run_plugin_endpoint(
    plugin_name: str,
    payload: PluginRunRequest,
    db: AsyncSession = Depends(get_db),
    _auth: None = Depends(require_permission(Permission.PLUGIN_EXECUTE)),
) -> dict:
    """Manually execute a plugin against a target value."""
    plugin = registry.get(plugin_name)
    if plugin is None:
        raise HTTPException(status_code=404, detail=f"Plugin '{plugin_name}' not found")

    # Resolve target type
    target_type = payload.target_type
    if target_type is None:
        from argus.api.targets import classify_target
        target_type = classify_target(payload.target_value)

    # Run the plugin
    result = await run_plugin(
        plugin,
        payload.target_value,
        target_type,
        timeout=payload.timeout,
    )

    return {
        "plugin_name": plugin_name,
        "target_value": payload.target_value,
        "target_type": target_type,
        **result,
    }
