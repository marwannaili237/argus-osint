from __future__ import annotations

import logging

import aiohttp

from argus.plugins.runner import BasePlugin, PluginInfo

logger = logging.getLogger(__name__)


class DarkwebPlugin(BasePlugin):
    @property
    def info(self) -> PluginInfo:
        return PluginInfo(
            name="darkweb",
            display_name="Dark Web Search",
            description="Search dark web sources for domain, email, or username mentions",
            supported_types=["domain", "email", "username"],
            tags=["darkweb", "threat", "breach"],
        )

    async def run(self, target_value: str, target_type: str, **kwargs) -> dict:
        darkweb_mentions = []
        paste_sites = []
        exposed_credentials = False
        settings = kwargs.get("settings")

        if settings and getattr(settings, "VIRUSTOTAL_API_KEY", None):
            try:
                async with aiohttp.ClientSession() as session:
                    headers = {"x-apikey": settings.VIRUSTOTAL_API_KEY}
                    query_param = target_value
                    url = f"https://www.virustotal.com/api/v3/darkweb/search?query={query_param}"
                    async with session.get(url, headers=headers, timeout=aiohttp.ClientTimeout(total=15)) as resp:
                        if resp.status == 200:
                            data = await resp.json()
                            for item in data.get("data", [])[:20]:
                                darkweb_mentions.append({"source": item.get("source", ""),
                                                        "date": item.get("date", ""),
                                                        "snippet": item.get("text", "")[:200]})
            except Exception as e:
                logger.warning("VirusTotal darkweb search failed: %s", e)

        return {
            "darkweb_mentions": darkweb_mentions,
            "paste_sites": paste_sites,
            "exposed_credentials": exposed_credentials,
        }
