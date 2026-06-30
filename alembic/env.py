"""
Argus OSINT – Alembic Async Environment

Provides the migration environment that imports the Argus Base metadata
and all models so autogenerate can detect schema changes.

Uses asyncio for async database connectivity.
"""

from __future__ import annotations

import asyncio
import logging
from logging.config import fileConfig
from pathlib import Path
from typing import Any

from alembic import context
from sqlalchemy import pool
from sqlalchemy.engine import Connection
from sqlalchemy.ext.asyncio import async_engine_from_config

# ── Alembic Config ────────────────────────────────────────────────────

config = context.config

if config.config_file_name is not None:
    fileConfig(config.config_file_name)

# ── Import Argus models and Base ────────────────────────────────────

from argus.database import Base
import argus.models  # noqa: F401 – ensures all models register with Base

target_metadata = Base.metadata

logger = logging.getLogger("alembic.env")


# ── Database URL from settings ────────────────────────────────────────

def get_url() -> str:
    """Resolve the database URL from Argus settings."""
    from argus.config import get_settings
    return get_settings().DATABASE_URL


# ── Offline / Online Migration Functions ─────────────────────────────

def run_migrations_offline(target_metadata: Any) -> None:
    """Run migrations in 'offline' mode.

    Generates SQL scripts without connecting to the database.
    """
    url = get_url()
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )

    with context.begin_transaction():
        context.run_migrations()
    logger.info("Offline migrations complete")


def do_run_migrations(connection: Connection) -> None:
    """Execute migrations against a live connection."""
    context.configure(
        connection=connection,
        target_metadata=target_metadata,
    )

    with context.begin_transaction():
        context.run_migrations()
    logger.info("Online migrations complete")


async def run_async_migrations() -> None:
    """Run migrations using an async engine."""
    url = get_url()

    # Convert async URL for sync connect if needed, or use aiosqlite driver
    configuration = config.get_section(config.config_ini_section, {})
    configuration["sqlalchemy.url"] = url

    connectable = async_engine_from_config(
        configuration,
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )

    async with connectable.connect() as connection:
        await connection.run_sync(do_run_migrations)

    await connectable.dispose()


def run_migrations_online(target_metadata: Any) -> None:
    """Run migrations in 'online' mode (async)."""
    asyncio.run(run_async_migrations())


# ── Entry Point ──────────────────────────────────────────────────────

if context.is_offline_mode():
    run_migrations_offline(target_metadata)
else:
    run_migrations_online(target_metadata)
