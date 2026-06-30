"""Argus OSINT Plugin System - Base classes, registry, and executor."""

import asyncio
import logging
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class PluginResult:
    """Result returned by a plugin execution."""
    plugin_name: str
    status: str  # success, error, timeout, cached
    data: dict = field(default_factory=dict)
    execution_time: float = 0.0
    cached: bool = False
    error_message: str | None = None


class PluginError(Exception):
    """Custom exception for plugin errors."""
    pass


class PluginTimeoutError(PluginError):
    """Raised when a plugin exceeds its timeout."""
    pass


class BasePlugin(ABC):
    """Base class for all Argus OSINT plugins."""
    name: str = "base_plugin"
    target_types: list[str] = []
    timeout_seconds: int = 30
    retry_count: int = 2
    _health_ok: bool = True
    _consecutive_failures: int = 0
    _cache: dict[str, tuple[float, PluginResult]] = {}
    _cache_ttl: int = 300  # 5 minutes

    @abstractmethod
    async def run(self, target: str) -> PluginResult:
        """Execute the plugin against a target. Must be implemented by subclasses."""
        pass

    async def safe_run(self, target: str) -> PluginResult:
        """Run with timeout, retry, caching, and health tracking."""
        cache_key = f"{self.name}:{target}"

        # Check cache
        if cache_key in self._cache:
            ts, cached_result = self._cache[cache_key]
            if time.time() - ts < self._cache_ttl:
                cached_result.cached = True
                cached_result.execution_time = 0.0
                return cached_result

        last_error = None
        for attempt in range(self.retry_count + 1):
            try:
                start = time.time()
                result = await asyncio.wait_for(
                    self.run(target), timeout=self.timeout_seconds
                )
                result.execution_time = round(time.time() - start, 3)

                # Update health
                if result.status == "success":
                    self._consecutive_failures = 0
                    self._health_ok = True
                else:
                    self._consecutive_failures += 1
                    if self._consecutive_failures >= 3:
                        self._health_ok = False

                # Cache successful results
                if result.status == "success":
                    self._cache[cache_key] = (time.time(), result)

                return result

            except asyncio.TimeoutError:
                last_error = "Timeout"
                logger.warning(f"Plugin {self.name} timed out (attempt {attempt + 1})")
            except Exception as e:
                last_error = str(e)
                logger.warning(f"Plugin {self.name} error (attempt {attempt + 1}): {e}")

        self._consecutive_failures += 1
        return PluginResult(
            plugin_name=self.name, status="error",
            data={}, error_message=f"After {self.retry_count + 1} retries: {last_error}"
        )

    @property
    def is_healthy(self) -> bool:
        return self._health_ok


class PluginInfo:
    """Metadata about a registered plugin."""
    def __init__(self, plugin: BasePlugin):
        self.name = plugin.name
        self.target_types = plugin.target_types
        self.timeout_seconds = plugin.timeout_seconds
        self.is_healthy = plugin.is_healthy


class PluginRegistry:
    """Registry that manages all plugins and executes them."""
    def __init__(self):
        self._plugins: dict[str, BasePlugin] = {}

    def register(self, plugin: BasePlugin):
        """Register a plugin instance."""
        self._plugins[plugin.name] = plugin
        logger.debug(f"Registered plugin: {plugin.name}")

    def get(self, name: str) -> BasePlugin | None:
        return self._plugins.get(name)

    def get_all(self) -> list[BasePlugin]:
        return list(self._plugins.values())

    def get_plugins_for_target(self, target_type: str) -> list[BasePlugin]:
        return [p for p in self._plugins.values() if target_type in p.target_types or "unknown" in p.target_types]


# Global registry
registry = PluginRegistry()


async def run_plugin(plugin_name: str, target: str) -> PluginResult:
    """Run a specific plugin by name."""
    plugin = registry.get(plugin_name)
    if not plugin:
        return PluginResult(plugin_name=plugin_name, status="error", data={}, error_message="Plugin not found")
    return await plugin.safe_run(target)


async def run_all_for_target(target: str, target_type: str | None = None) -> list[PluginResult]:
    """Run all matching plugins for a target type."""
    if target_type is None:
        from argus.plugins.classifier import classify_target
        target_type = classify_target(target)
    plugins = registry.get_plugins_for_target(target_type)
    if not plugins:
        return []
    tasks = [plugin.safe_run(target) for plugin in plugins]
    results = await asyncio.gather(*tasks, return_exceptions=True)
    output = []
    for r in results:
        if isinstance(r, PluginResult):
            output.append(r)
        elif isinstance(r, Exception):
            output.append(PluginResult(plugin_name="unknown", status="error", data={}, error_message=str(r)))
    return output


# ─── Register ALL plugins ───────────────────────────────────────────────

def _register_all():
    """Import and register all plugin classes."""
    pass  # Registration handled by _auto_register()


# Build the ALL_PLUGINS dict grouped by target type
def refresh_all_plugins_list() -> dict[str, list[PluginInfo]]:
    """Refresh and return the ALL_PLUGINS dict mapping target_type -> list of PluginInfo."""
    result: dict[str, list[PluginInfo]] = {}
    for plugin in registry.get_all():
        for tt in plugin.target_types:
            if tt not in result:
                result[tt] = []
            result[tt].append(PluginInfo(plugin))
    return result


ALL_PLUGINS: dict[str, list[PluginInfo]] = {}


# ─── Auto-register all plugins on import ────────────────────────────────

def _auto_register():
    """Import all plugin modules to trigger registration."""
    import importlib
    plugin_modules = [
        "argus.plugins.dns_history_plugin",
        "argus.plugins.website_screenshot_plugin",
        "argus.plugins.favicon_hash_plugin",
        "argus.plugins.ip_geolocation_plugin",
        "argus.plugins.honeypot_detector_plugin",
        "argus.plugins.darkweb_plugin",
        "argus.plugins.security_headers_plugin",
        "argus.plugins.captcha_detector_plugin",
        "argus.plugins.reverse_image_plugin",
        # Email plugins
        "argus.plugins.email_fullcontact",
        "argus.plugins.email_hunter",
        "argus.plugins.email_clearbit",
        "argus.plugins.email_header",
        "argus.plugins.email_gravatar",
        "argus.plugins.email_smtp",
        "argus.plugins.email_forwarding",
        "argus.plugins.email_domain_whois",
        "argus.plugins.email_reputation_enhanced",
        "argus.plugins.email_thread",
        "argus.plugins.email_to_phone",
        # Social plugins
        "argus.plugins.social_sherlock",
        "argus.plugins.social_telegram",
        "argus.plugins.social_reddit",
        "argus.plugins.social_twitter",
        "argus.plugins.social_instagram",
        "argus.plugins.social_discord",
        # Network plugins
        "argus.plugins.network_traceroute",
        "argus.plugins.network_asn",
        "argus.plugins.network_cdn_waf",
        "argus.plugins.network_zone_transfer",
        "argus.plugins.network_ipv6",
        "argus.plugins.network_dns_monitor",
        "argus.plugins.network_cert_pinning",
        "argus.plugins.network_version_fingerprint",
        # Web plugins
        "argus.plugins.web_crawler",
        "argus.plugins.web_archive",
        "argus.plugins.web_broken_links",
        "argus.plugins.web_js_analyzer",
        "argus.plugins.web_doc_metadata",
        "argus.plugins.web_connected_sites",
        "argus.plugins.web_version_fingerprint",
        # AI plugins
        "argus.plugins.ai_classifier",
        "argus.plugins.ai_correlation",
        "argus.plugins.ai_ioc",
        "argus.plugins.ai_threat_scoring",
        "argus.plugins.ai_nl_query",
        "argus.plugins.ai_sentiment",
        "argus.plugins.ai_report_generator",
    ]

    # Each plugin module should have a class that inherits BasePlugin.
    # We discover and register them.
    for module_name in plugin_modules:
        try:
            mod = importlib.import_module(module_name)
            for attr_name in dir(mod):
                attr = getattr(mod, attr_name)
                if (isinstance(attr, type) and issubclass(attr, BasePlugin)
                        and attr is not BasePlugin
                        and not attr.__name__.startswith("_")):
                    try:
                        instance = attr()
                        registry.register(instance)
                    except Exception as e:
                        logger.warning(f"Could not instantiate {module_name}.{attr_name}: {e}")
        except Exception as e:
            logger.warning(f"Could not import plugin module {module_name}: {e}")

    global ALL_PLUGINS
    ALL_PLUGINS = refresh_all_plugins_list()
    logger.info(f"Registered {len(registry.get_all())} plugins across {len(ALL_PLUGINS)} target types")


# Auto-register on module import
_auto_register()
