"""
Argus OSINT – Health Check Router

Provides liveness and readiness probes for container orchestration
and monitoring systems.
"""

from __future__ import annotations

import logging
import time
from datetime import datetime, timezone

from fastapi import APIRouter
from sqlalchemy import text

from argus.database import async_session_factory
from argus.startup import run_startup_checks

logger = logging.getLogger(__name__)

router = APIRouter(tags=["health"])

# Track application start time for uptime calculation
_app_start_time: float = time.monotonic()


@router.get("/health")
async def health_check() -> dict:
    """Liveness probe – confirms the application process is running."""
    uptime = round(time.monotonic() - _app_start_time, 2)
    return {
        "status": "healthy",
        "version": "2.0.0",
        "uptime": uptime,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


@router.get("/health/ready")
async def readiness_check() -> dict:
    """Readiness probe – confirms all dependencies are reachable."""
    checks: dict[str, dict] = {}
    overall_status = "ready"

    # Database connectivity
    try:
        async with async_session_factory() as session:
            await session.execute(text("SELECT 1"))
        checks["database"] = {"status": "connected", "detail": "Database connection OK"}
    except Exception as exc:
        checks["database"] = {"status": "error", "detail": str(exc)}
        overall_status = "not_ready"

    # Configuration loaded
    try:
        from argus.config import get_settings
        _settings = get_settings()
        checks["configuration"] = {"status": "loaded", "detail": "Configuration loaded successfully"}
    except Exception as exc:
        checks["configuration"] = {"status": "error", "detail": str(exc)}
        overall_status = "not_ready"

    # Plugins
    from argus.plugins import refresh_all_plugins_list, ALL_PLUGINS
    refresh_all_plugins_list()
    checks["plugins"] = {
        "status": "ok",
        "detail": f"{len(ALL_PLUGINS)} plugin(s) registered",
    }

    return {
        "status": overall_status,
        "version": "2.0.0",
        "checks": checks,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
