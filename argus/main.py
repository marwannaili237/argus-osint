"""
Argus OSINT – Main Application Entry Point

Creates the FastAPI application with middleware stack, includes all
API routers, and manages startup/shutdown lifecycle including
graceful shutdown on SIGTERM/SIGINT.
"""

from __future__ import annotations

import asyncio
import logging
import os
import signal
import sys
import time
from contextlib import asynccontextmanager
from typing import AsyncGenerator

from fastapi import FastAPI, Request, Response, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

# ── Logging Setup ────────────────────────────────────────────────────

from argus.config import get_settings

settings = get_settings()

logging.basicConfig(
    level=getattr(logging, settings.LOG_LEVEL, logging.INFO),
    format="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S%z",
)
logger = logging.getLogger("argus")

# ── Application Start Time ──────────────────────────────────────────
_app_start_time: float = time.monotonic()


# ── Rate Limiter (in-memory, per-IP) ────────────────────────────────

class _SimpleRateLimiter:
    """Simple sliding-window rate limiter keyed by IP address."""

    def __init__(self, max_requests: int = 100, window_seconds: int = 60) -> None:
        self.max_requests = max_requests
        self.window = window_seconds
        self._buckets: dict[str, list[float]] = {}

    def is_allowed(self, key: str) -> bool:
        now = time.monotonic()
        cutoff = now - self.window
        bucket = self._buckets.setdefault(key, [])
        self._buckets[key] = bucket = [t for t in bucket if t > cutoff]
        if len(bucket) >= self.max_requests:
            return False
        bucket.append(now)
        return True


_rate_limiter = _SimpleRateLimiter(
    max_requests=100,
    window_seconds=60,
)


# ── Graceful Shutdown State ─────────────────────────────────────────

_shutdown_event = asyncio.Event()
_pending_tasks: set[asyncio.Task] = set()


# ── Lifecycle ────────────────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Application lifespan – startup and shutdown hooks."""
    # ── Startup ─────────────────────────────────────────────────
    logger.info("╔══════════════════════════════════════════════╗")
    logger.info("║          Argus OSINT Platform v2.0.0          ║")
    logger.info("╚══════════════════════════════════════════════╝")
    logger.info("Starting application (env: %s) …", settings.APP_ENV)

    # Import all models to ensure they're registered with Base.metadata
    import argus.models  # noqa: F401

    # Initialize database tables
    from argus.database import init_db
    await init_db()
    logger.info("Database initialized")

    # Run startup validation checks
    from argus.startup import run_startup_checks
    report = await run_startup_checks()
    if report.errors:
        logger.error("Startup found %d CRITICAL error(s):", len(report.errors))
        for err in report.errors:
            logger.error("  ✖ %s", err)
    if report.warnings:
        logger.warning("Startup found %d warning(s):", len(report.warnings))
        for warn in report.warnings:
            logger.warning("  ⚠ %s", warn)
    if not report.errors:
        logger.info("All startup checks passed ✓")

    # Refresh plugin list
    from argus.plugins import refresh_all_plugins_list
    refresh_all_plugins_list()

    logger.info("Application startup complete (took %.3fs)", report.elapsed)

    yield

    # ── Shutdown ────────────────────────────────────────────────
    logger.info("Shutting down Argus OSINT …")

    # Cancel pending background tasks
    for task in _pending_tasks:
        if not task.done():
            task.cancel()
            try:
                await asyncio.wait_for(task, timeout=5.0)
            except (asyncio.CancelledError, asyncio.TimeoutError):
                pass

    # Close database connections
    from argus.database import close_db
    await close_db()

    logger.info("Shutdown complete")


# ── Create FastAPI App ────────────────────────────────────────────────

app = FastAPI(
    title="Argus OSINT",
    description="Open-Source Intelligence gathering and analysis platform",
    version="2.0.0",
    docs_url="/api/docs",
    redoc_url="/api/redoc",
    openapi_url="/api/openapi.json",
    lifespan=lifespan,
)


# ── Middleware Stack ─────────────────────────────────────────────────

# 1. CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origin_list,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# 2. Request Logging Middleware
@app.middleware("http")
async def request_logging_middleware(request: Request, call_next) -> Response:
    """Log method, path, status code, and response duration for every request."""
    start = time.monotonic()
    response: Response = await call_next(request)
    duration_ms = round((time.monotonic() - start) * 1000, 2)
    logger.info(
        "%s %s → %d (%.1fms)",
        request.method,
        request.url.path,
        response.status_code,
        duration_ms,
    )
    return response


# 3. Rate Limiting Middleware
@app.middleware("http")
async def rate_limiting_middleware(request: Request, call_next) -> Response:
    """Enforce per-IP rate limits. Exempt health checks and docs."""
    if request.url.path in ("/health", "/health/ready", "/api/docs", "/api/redoc", "/api/openapi.json"):
        return await call_next(request)

    client_ip = request.client.host if request.client else "unknown"
    if not _rate_limiter.is_allowed(client_ip):
        return JSONResponse(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            content={"detail": "Rate limit exceeded. Try again in 60 seconds."},
        )

    return await call_next(request)


# 4. IP Allowlist Middleware
@app.middleware("http")
async def ip_allowlist_middleware(request: Request, call_next) -> Response:
    """Block requests from IPs not in the configured allowlist."""
    allowlist = settings.ip_allowlist_set
    if allowlist is not None:
        client_ip = request.client.host if request.client else "unknown"
        if client_ip not in allowlist:
            logger.warning("Blocked request from non-allowlisted IP: %s", client_ip)
            return JSONResponse(
                status_code=status.HTTP_403_FORBIDDEN,
                content={"detail": "Access denied from your IP address"},
            )

    return await call_next(request)


# 5. API Key Authentication Middleware
@app.middleware("http")
async def api_key_auth_middleware(request: Request, call_next) -> Response:
    """Check X-API-Key header for API key authentication.

    If a valid API key is found, attach the key info to request.state.
    If not, let the request continue (JWT/session auth may apply).
    """
    raw_key = request.headers.get("X-API-Key")
    if raw_key:
        from argus.api.api_keys import validate_api_key
        from argus.database import async_session_factory

        try:
            async with async_session_factory() as db:
                api_key = await validate_api_key(raw_key, db)
                await db.commit()
            request.state.current_api_key = api_key
        except Exception as exc:
            # Authentication already raises HTTPException in validate_api_key
            # but middleware swallows it, so we need to return the error here
            return JSONResponse(
                status_code=exc.status_code if hasattr(exc, "status_code") else 401,
                content={"detail": str(exc.detail) if hasattr(exc, "detail") else str(exc)},
            )

    return await call_next(request)


# 6. PII Redaction Middleware
@app.middleware("http")
async def pii_redaction_middleware(request: Request, call_next) -> Response:
    """Redact PII from JSON response bodies for non-admin users.

    Skips non-JSON responses, docs, and admin users.
    """
    response: Response = await call_next(request)

    # Skip for non-JSON, docs, and internal paths
    content_type = response.headers.get("content-type", "")
    if (
        "application/json" not in content_type
        or request.url.path.startswith("/api/docs")
        or request.url.path.startswith("/api/redoc")
        or request.url.path.startswith("/api/openapi")
        or request.url.path in ("/health", "/health/ready")
    ):
        return response

    # Determine if user is admin
    user = getattr(request.state, "current_user", None)
    is_admin = user is not None and (user.is_superuser or user.role == "admin")

    if is_admin:
        return response

    # Read and redact response body
    from argus.security.pii_redact import redact_response_body

    body = response.body
    redacted = redact_response_body(body, is_admin=False)

    if redacted != body:
        response = Response(
            content=redacted,
            status_code=response.status_code,
            headers=dict(response.headers),
            media_type=response.media_type,
        )

    return response


# ── Include API Routers ──────────────────────────────────────────────

from argus.api.health import router as health_router
from argus.api.targets import router as targets_router
from argus.api.investigations import router as investigations_router
from argus.api.plugins import router as plugins_router
from argus.api.api_keys import router as api_keys_router
from argus.api.users import router as users_router
from argus.api.dashboard import router as dashboard_router

app.include_router(health_router)
app.include_router(targets_router, prefix="/api/v1")
app.include_router(investigations_router, prefix="/api/v1")
app.include_router(plugins_router, prefix="/api/v1")
app.include_router(api_keys_router, prefix="/api/v1")
app.include_router(users_router, prefix="/api/v1")
app.include_router(dashboard_router, prefix="/api/v1")


# ── Signal Handlers ──────────────────────────────────────────────────

def _handle_signal(signum: int, frame: object | None) -> None:
    """Handle SIGTERM/SIGINT for graceful shutdown."""
    sig_name = signal.Signals(signum).name
    logger.info("Received %s – initiating graceful shutdown …", sig_name)
    _shutdown_event.set()
    # In a uvicorn context, this signals the server to stop
    os.kill(os.getpid(), signal.SIGINT)


signal.signal(signal.SIGTERM, _handle_signal)
signal.signal(signal.SIGINT, _handle_signal)


# ── Direct Run Entry Point ──────────────────────────────────────────

if __name__ == "__main__":
    import uvicorn

    logger.info("Starting Argus OSINT via uvicorn on 0.0.0.0:8000")
    uvicorn.run(
        "argus.main:app",
        host="0.0.0.0",
        port=8000,
        reload=settings.is_development,
        log_level=settings.LOG_LEVEL.lower(),
        timeout_graceful_shutdown=30,
    )
