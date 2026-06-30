from __future__ import annotations

import logging

import aiohttp

from argus.plugins.runner import BasePlugin, PluginInfo

logger = logging.getLogger(__name__)


class HoneypotDetectorPlugin(BasePlugin):
    @property
    def info(self) -> PluginInfo:
        return PluginInfo(
            name="honeypot_detector",
            display_name="Honeypot Detector",
            description="Check if an IP is a known honeypot via Shodan Honeyscore",
            supported_types=["ip"],
            tags=["ip", "threat", "honeypot"],
            requires_api_key="SHODAN_API_KEY",
        )

    async def run(self, target_value: str, target_type: str, **kwargs) -> dict:
        honeyscore = 0.0
        risk_level = "unknown"
        sources_checked = []
        settings = kwargs.get("settings")

        if settings and getattr(settings, "SHODAN_API_KEY", None):
            try:
                async with aiohttp.ClientSession() as session:
                    url = f"https://api.shodan.io/labs/honeyscore/{target_value}?key={settings.SHODAN_API_KEY}"
                    async with session.get(url, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                        if resp.status == 200:
                            score = await resp.text()
                            honeyscore = float(score)
                            sources_checked.append("shodan_honeyscore")
            except Exception as e:
                logger.warning("Shodan honeyscore failed: %s", e)

        if honeyscore >= 0.8:
            risk_level = "critical"
        elif honeyscore >= 0.5:
            risk_level = "high"
        elif honeyscore >= 0.2:
            risk_level = "medium"
        elif honeyscore > 0.0:
            risk_level = "low"
        else:
            risk_level = "none"

        return {
            "honeyscore": honeyscore,
            "risk_level": risk_level,
            "sources_checked": sources_checked,
        }
