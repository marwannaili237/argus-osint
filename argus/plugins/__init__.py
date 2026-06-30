"""
Argus OSINT – Plugin Runner

Lightweight plugin registry and execution engine.  Plugins are discovered
and registered at import time.  Each plugin declares which target types
it supports and provides a coroutine-based ``run`` method.
"""

from __future__ import annotations

import abc
import logging
import time
from dataclasses import dataclass, field
from typing import Any, AsyncIterator, Callable

logger = logging.getLogger(__name__)


# ── Plugin Descriptor ────────────────────────────────────────────────

@dataclass
class PluginInfo:
    """Metadata describing a registered plugin."""

    name: str
    display_name: str
    description: str = ""
    version: str = "1.0.0"
    supported_types: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)
    requires_api_key: str | None = None


# ── Base Plugin ──────────────────────────────────────────────────────

class BasePlugin(abc.ABC):
    """Abstract base class that every Argus plugin must implement."""

    @property
    @abc.abstractmethod
    def info(self) -> PluginInfo:
        """Return metadata about this plugin."""

    @abc.abstractmethod
    async def run(self, target_value: str, target_type: str, **kwargs: Any) -> dict[str, Any]:
        """Execute the plugin against a target and return structured results.

        Args:
            target_value: The target identifier (domain, IP, email, etc.)
            target_type: The classified type of the target
            **kwargs: Additional context (config, api keys, etc.)

        Returns:
            A dictionary of plugin-specific results.

        Raises:
            PluginError: On recoverable failure
            PluginTimeoutError: If execution exceeds the timeout
        """


# ── Exceptions ─────────────────────────────────────────────────────────

class PluginError(Exception):
    """Base exception for plugin errors."""

    def __init__(self, plugin_name: str, message: str) -> None:
        self.plugin_name = plugin_name
        self.message = message
        super().__init__(f"Plugin '{plugin_name}': {message}")


class PluginTimeoutError(PluginError):
    """Raised when a plugin exceeds its execution time limit."""


# ── Registry ─────────────────────────────────────────────────────────

class PluginRegistry:
    """Central registry for all OSINT plugins."""

    def __init__(self) -> None:
        self._plugins: dict[str, BasePlugin] = {}

    def register(self, plugin: BasePlugin) -> None:
        """Register a plugin instance by its unique name."""
        name = plugin.info.name
        if name in self._plugins:
            logger.warning("Overwriting existing plugin: %s", name)
        self._plugins[name] = plugin
        logger.debug("Registered plugin: %s (%s)", name, plugin.info.display_name)

    def get(self, name: str) -> BasePlugin | None:
        """Retrieve a registered plugin by name."""
        return self._plugins.get(name)

    def unregister(self, name: str) -> None:
        """Remove a plugin from the registry."""
        self._plugins.pop(name, None)

    def all(self) -> dict[str, BasePlugin]:
        """Return all registered plugins."""
        return dict(self._plugins)

    def by_target_type(self, target_type: str) -> list[BasePlugin]:
        """Return all plugins that support a given target type."""
        return [
            p
            for p in self._plugins.values()
            if target_type in p.info.supported_types or "*" in p.info.supported_types
        ]

    def grouped_by_type(self) -> dict[str, list[PluginInfo]]:
        """Return plugins grouped by the target types they support."""
        groups: dict[str, list[PluginInfo]] = {}
        for plugin in self._plugins.values():
            info = plugin.info
            for t in info.supported_types:
                groups.setdefault(t, []).append(info)
        return groups

    @property
    def count(self) -> int:
        return len(self._plugins)

    @property
    def all_plugin_infos(self) -> list[PluginInfo]:
        return [p.info for p in self._plugins.values()]


# ── Global Singleton ─────────────────────────────────────────────────

registry = PluginRegistry()


# Convenience alias used by the startup checker
ALL_PLUGINS: list[PluginInfo] = []


def refresh_all_plugins_list() -> None:
    """Sync the module-level ALL_PLUGINS list with the current registry state."""
    global ALL_PLUGINS
    ALL_PLUGINS = registry.all_plugin_infos


# ── Execution Runner ──────────────────────────────────────────────────

async def run_plugin(
    plugin: BasePlugin,
    target_value: str,
    target_type: str,
    timeout: float = 30.0,
    **kwargs: Any,
) -> dict[str, Any]:
    """Execute a single plugin with timing and timeout enforcement.

    Returns a dict with keys: data, execution_time, status, error_message.
    """
    import asyncio

    start = time.monotonic()
    try:
        result = await asyncio.wait_for(
            plugin.run(target_value, target_type, **kwargs),
            timeout=timeout,
        )
        elapsed = time.monotonic() - start
        return {
            "data": result,
            "execution_time": round(elapsed, 4),
            "status": "success",
            "error_message": None,
        }
    except asyncio.TimeoutError:
        elapsed = time.monotonic() - start
        return {
            "data": {},
            "execution_time": round(elapsed, 4),
            "status": "timeout",
            "error_message": f"Plugin '{plugin.info.name}' timed out after {timeout}s",
        }
    except PluginError as exc:
        elapsed = time.monotonic() - start
        return {
            "data": {},
            "execution_time": round(elapsed, 4),
            "status": "error",
            "error_message": str(exc),
        }
    except Exception as exc:
        elapsed = time.monotonic() - start
        logger.exception("Unexpected error in plugin %s", plugin.info.name)
        return {
            "data": {},
            "execution_time": round(elapsed, 4),
            "status": "error",
            "error_message": f"Unexpected error: {exc}",
        }


async def run_all_for_target(
    target_value: str,
    target_type: str,
    timeout_per_plugin: float = 30.0,
    **kwargs: Any,
) -> list[dict[str, Any]]:
    """Run all matching plugins for a given target type concurrently.

    Returns a list of result dicts (one per plugin).
    """
    import asyncio

    plugins = registry.by_target_type(target_type)
    if not plugins:
        return []

    tasks = [
        run_plugin(p, target_value, target_type, timeout=timeout_per_plugin, **kwargs)
        for p in plugins
    ]
    return await asyncio.gather(*tasks)
